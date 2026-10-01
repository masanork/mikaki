export function weaveProfile(origin: string) {
  let seed = 2166136261;
  for (const c of new URL(origin).origin) seed = Math.imul(seed ^ c.charCodeAt(0), 16777619);
  seed >>>= 0;
  return {
    hue: (seed + 125) % 360,
    spacing: 28 + (seed % 53),
    strip: 0.12 + ((seed >>> 8) % 19) / 100,
    aspect: 0.65 + ((seed >>> 16) % 90) / 100,
    pattern: (seed >>> 24) % 2,
    bend: 0.11 + (seed % 11) / 90,
    grainAngle: (seed % 24) + 4,
  };
}

// Cached bamboo material; only the grazing light is recomposited on each frame.
export function createWovenGate(
  scene: HTMLElement,
  canvas: HTMLCanvasElement,
  pageOrigin: string,
  rpOrigin: string,
  layout: 'gate' | 'fence' = 'gate',
) {
  const context = canvas.getContext('2d');
  if (!context) return null;
  const ctx: CanvasRenderingContext2D = context;
  const page = weaveProfile(pageOrigin),
    rp = weaveProfile(rpOrigin);
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  const material = document.createElement('canvas');
  const materialCanvasContext = material.getContext('2d');
  if (!materialCanvasContext) return null;
  const materialContext: CanvasRenderingContext2D = materialCanvasContext;
  let width = 0,
    height = 0,
    raf = 0,
    last = 0,
    animationTime = 0,
    busy = false,
    destroyed = false,
    x = 0.24,
    y = 0.28,
    tx = x,
    ty = y,
    materialKey = '';
  const clamp = (v: number, a: number, b: number) => Math.max(a, Math.min(b, v));
  function draw(time: number) {
    if (
      destroyed ||
      !Number.isFinite(width) ||
      !Number.isFinite(height) ||
      width <= 0 ||
      height <= 0
    )
      return;
    const w = width,
      h = height,
      animated = !reduced.matches && !busy && !document.hidden;
    const power = clamp(65, 0, 100) / 100;
    const orbit = animated ? time / 8500 : 0;
    const lx = clamp(x + (animated ? Math.sin(orbit) * 0.13 * power : 0), 0.05, 0.95),
      ly = clamp(y + (animated ? Math.sin(orbit * 0.73) * 0.09 * power : 0), 0.05, 0.95);
    scene.style.setProperty('--light-x', `${lx * 100}%`);
    const nextKey = JSON.stringify([canvas.width, canvas.height, [page, rp], layout, 0.9, 14]);
    if (nextKey !== materialKey) {
      ctx.clearRect(0, 0, w, h);
      ctx.fillStyle = '#02070e';
      ctx.fillRect(0, 0, w, h);
      const gap = Math.max(4, (clamp(0.9, 0.4, 2.2) / 100) * w),
        curvature = clamp(14, 0, 26) / 100;
      const fence = layout === 'fence';
      for (let side = 0; side < (fence ? 1 : 2); side++) {
        const colorHue = side ? rp.hue : page.hue;
        const profile = side ? rp : page;
        const spacing = side ? rp.spacing : page.spacing,
          bend = side ? rp.bend : page.bend;
        const color = `hsl(${colorHue} 42% 25%)`,
          glint = `hsl(${colorHue} 52% 69%)`;
        const direction = side ? 1 : -1,
          outer = side ? w + 24 : -24;
        function edge(y: number) {
          const v = clamp(y / h, 0, 1),
            bow = Math.sin(v * Math.PI) * w * 0.006 * curvature * (0.8 + bend);
          return w * 0.5 + direction * (gap * 0.5 + bow);
        }
        function leafPath(inset = 0) {
          ctx.beginPath();
          if (fence) {
            ctx.rect(-24, -20, w + 48, h + 40);
            return;
          }
          ctx.moveTo(outer, -20);
          ctx.lineTo(edge(0) + direction * inset, -20);
          for (let y = 0; y <= h; y += 8) ctx.lineTo(edge(y) + direction * inset, y);
          ctx.lineTo(edge(h) + direction * inset, h + 20);
          ctx.lineTo(outer, h + 20);
          ctx.closePath();
        }
        ctx.save();
        leafPath();
        ctx.clip();
        ctx.fillStyle = '#07111c';
        ctx.fillRect(0, 0, w, h);
        const glow = ctx.createRadialGradient(w * 0.24, h * 0.28, 0, w * 0.24, h * 0.28, w * 0.8);
        glow.addColorStop(0, `hsl(${colorHue} 45% 28% / .28)`);
        glow.addColorStop(1, 'transparent');
        ctx.fillStyle = glow;
        ctx.fillRect(0, 0, w, h);
        // Each leaf has its own plane and inner edge; overscan keeps the outer edges filled.
        function warp(a: number, b: number): [number, number] {
          const u = a / (fence ? w : w * 0.5),
            bb = h * 0.5 + (b - h * 0.5) * profile.aspect,
            v = (bb - h * 0.5) / h;
          if (fence) return [a, bb + Math.sin(u * Math.PI) * Math.cos(v * Math.PI) * h * 0.008];
          const yy =
            h * 0.5 +
            (bb - h * 0.5) * (1 - u * 0.08) +
            Math.sin(u * Math.PI) * Math.cos(v * Math.PI) * h * 0.03 * curvature;
          const inner = edge(yy);
          const arc = Math.sin(clamp(yy / h, 0, 1) * Math.PI),
            projected = u >= 0 ? Math.pow(u, 1 - 0.36 * curvature * arc) : u;
          return [
            outer +
              (inner - outer) * projected -
              direction * Math.sin(u * Math.PI) * arc * w * 0.045 * curvature,
            yy,
          ];
        }
        const ribbonWidth = spacing * profile.strip;
        const shine = ctx.createLinearGradient(0, h * 0.1, w, h * 0.9);
        shine.addColorStop(0, color);
        shine.addColorStop(0.24, glint);
        shine.addColorStop(1, color);
        function ribbon(a: number, b: number, c: number, d: number, family: number) {
          const angle = family ? -Math.PI / 4 : Math.PI / 4,
            nx = -Math.sin(angle),
            ny = Math.cos(angle);
          const lit = clamp(0.46 + (nx * -0.26 + ny * -0.22) * 0.7, 0.1, 0.85);
          const steps = Math.max(2, Math.ceil(Math.hypot(c - a, d - b) / 24));
          function path(offset = 0) {
            ctx.beginPath();
            for (let i = 0; i <= steps; i++) {
              const t = i / steps,
                q = warp(a + (c - a) * t + nx * offset, b + (d - b) * t + ny * offset);
              if (!i) ctx.moveTo(...q);
              else ctx.lineTo(...q);
            }
          }
          ctx.globalAlpha = 1;
          ctx.lineWidth = ribbonWidth + 2.5;
          ctx.strokeStyle = '#020811';
          ctx.shadowColor = '#02070c';
          ctx.shadowBlur = 3;
          ctx.shadowOffsetX = 1.3;
          ctx.shadowOffsetY = 1.1;
          path();
          ctx.stroke();
          const grain = (((Math.round(a * 3 + b * 7) + family * 13) % 17) + 17) % 17;
          ctx.shadowColor = 'transparent';
          ctx.lineWidth = ribbonWidth;
          ctx.strokeStyle = `hsl(${colorHue} 42% ${22 + grain * 0.3}%)`;
          path();
          ctx.stroke();
          ctx.globalAlpha = 0.08 + lit * 0.24;
          ctx.lineWidth = ribbonWidth * 0.65;
          ctx.strokeStyle = shine;
          path(-ribbonWidth * 0.04);
          ctx.stroke();
          ctx.globalAlpha = 0.14 + lit * 0.22;
          ctx.lineWidth = 0.55;
          ctx.strokeStyle = glint;
          path(-ribbonWidth * 0.4);
          ctx.stroke();
          for (let fiber = 0; fiber < 5; fiber++) {
            ctx.globalAlpha = 0.045 + ((grain + fiber * 3) % 7) * 0.013;
            ctx.lineWidth = 0.25;
            path(ribbonWidth * (-0.3 + fiber * 0.14) + Math.sin(grain + fiber) * 0.18);
            ctx.stroke();
          }
          ctx.globalAlpha = 1;
        }
        const limit = Math.ceil((w + h) / spacing) + 2;
        for (let a = -limit; a <= limit; a++) ribbon(-h, -h + a * spacing, w, w + a * spacing, 0);
        for (let b = -limit; b <= limit; b++) ribbon(-h, h + b * spacing, w, -w + b * spacing, 1);
        for (let a = -limit; a <= limit; a++)
          for (let b = -limit; b <= limit; b++) {
            const over = profile.pattern ? (((a + b) % 4) + 4) % 4 < 2 : (a + b) % 2 === 0;
            if (!over) continue;
            const cx = ((b - a) * spacing) / 2,
              cy = ((a + b) * spacing) / 2;
            if (
              cx < -ribbonWidth ||
              cx > w * (fence ? 1 : 0.5) + ribbonWidth ||
              cy < -h * 0.5 ||
              cy > h * 1.5
            )
              continue;
            const delta = ribbonWidth * 1.1;
            ribbon(cx - delta, cy - delta, cx + delta, cy + delta, 0);
          }
        ctx.restore();
        if (fence) continue;
        // Continuous beveled meeting stiles make the two leaves legible behind the crossbar.
        const stileWidth = clamp(w * 0.013, 7, 15);
        ctx.save();
        leafPath();
        ctx.clip();
        function edgeStroke(offset: number, color: string, lineWidth: number) {
          ctx.beginPath();
          for (let y = -8; y <= h + 8; y += 8) {
            const xx = edge(y) + direction * offset;
            if (y === -8) ctx.moveTo(xx, y);
            else ctx.lineTo(xx, y);
          }
          ctx.strokeStyle = color;
          ctx.lineWidth = lineWidth;
          ctx.stroke();
        }
        edgeStroke(stileWidth * 0.5, '#020810', stileWidth + 6);
        edgeStroke(stileWidth * 0.5, `hsl(${colorHue} 22% 17%)`, stileWidth);
        edgeStroke(stileWidth * 0.3, `hsl(${colorHue} 28% 26%)`, stileWidth * 0.5);
        edgeStroke(1.5, `hsl(${colorHue} 40% 35%)`, 1.2);
        edgeStroke(stileWidth - 1, '#02070dbb', 2);
        ctx.restore();
      }
      material.width = canvas.width;
      material.height = canvas.height;
      materialContext.drawImage(canvas, 0, 0);
      materialKey = nextKey;
    } else {
      ctx.clearRect(0, 0, w, h);
      ctx.drawImage(material, 0, 0, w, h);
    }
    // Move grazing light across a cached material, leaving the bamboo and meeting line still.
    ctx.save();
    ctx.globalCompositeOperation = 'soft-light';
    const drift = animated ? Math.sin(orbit * 0.83 - 0.6) * w * 0.24 * power : 0;
    const sweep = lx * w + drift,
      lean = h * (0.25 + (animated ? Math.sin(orbit * 0.57) * 0.08 : 0));
    const band = ctx.createLinearGradient(sweep - w * 0.36, -lean, sweep + w * 0.36, h + lean);
    band.addColorStop(0, '#152433');
    band.addColorStop(0.32, '#304758');
    band.addColorStop(0.47, '#d4e6ed');
    band.addColorStop(0.53, '#dfedf0');
    band.addColorStop(0.7, '#395565');
    band.addColorStop(1, '#172636');
    ctx.globalAlpha = 0.2 + power * 0.58;
    ctx.fillStyle = band;
    ctx.fillRect(0, 0, w, h);
    const halo = ctx.createRadialGradient(lx * w, ly * h, w * 0.04, lx * w, ly * h, w * 0.62);
    halo.addColorStop(0, '#d2e5ed');
    halo.addColorStop(0.4, '#839da8');
    halo.addColorStop(1, '#172736');
    ctx.globalAlpha = power * 0.23;
    ctx.fillStyle = halo;
    ctx.fillRect(0, 0, w, h);
    ctx.restore();
    scene.dataset['lightPhase'] = animated ? String(Math.round(time / 100)) : 'still';
  }

  function tick(time: number) {
    raf = 0;
    if (destroyed || document.hidden || busy) return;
    if (reduced.matches) {
      // The preference can change before its media-query notification arrives.
      // Commit the static lighting frame before ending the animation loop.
      draw(animationTime);
      return;
    }
    if (time - last >= 42) {
      animationTime += Math.min(time - last, 100);
      x += (tx - x) * 0.2;
      y += (ty - y) * 0.2;
      draw(animationTime);
      last = time;
    }
    raf = requestAnimationFrame(tick);
  }
  function stop() {
    cancelAnimationFrame(raf);
    raf = 0;
  }
  function start() {
    if (
      !destroyed &&
      width > 0 &&
      height > 0 &&
      !raf &&
      !busy &&
      !reduced.matches &&
      !document.hidden
    ) {
      last = performance.now();
      raf = requestAnimationFrame(tick);
    }
  }
  function refresh() {
    if (destroyed) return;
    stop();
    draw(animationTime);
    start();
  }
  const observer = new ResizeObserver(() => {
    if (destroyed) return;
    const rect = scene.getBoundingClientRect();
    width = rect.width;
    height = rect.height;
    // Removed/collapsed scenes must not allocate or draw a zero-size canvas.
    if (!Number.isFinite(width) || !Number.isFinite(height) || width <= 0 || height <= 0) {
      width = height = 0;
      stop();
      return;
    }
    // Bound memory on high-density and very large displays.
    const dpr = Math.min(devicePixelRatio || 1, 1.25, 1800 / Math.max(width, height));
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    draw(animationTime);
    start();
  });
  observer.observe(scene);
  function pointer(event: PointerEvent) {
    if (destroyed || event.pointerType !== 'mouse' || busy || reduced.matches) return;
    const rect = scene.getBoundingClientRect();
    // Pointer events can arrive before ResizeObserver delivers the backing size.
    // Normalize with this event's measured bounds, never the uninitialized buffer.
    if (rect.width <= 0 || rect.height <= 0) return;
    const horizontal = (event.clientX - rect.left) / rect.width;
    const vertical = (event.clientY - rect.top) / rect.height;
    if (!Number.isFinite(horizontal) || !Number.isFinite(vertical)) return;
    tx = clamp(horizontal, 0.05, 0.95);
    ty = clamp(vertical, 0.05, 0.95);
  }
  function leave() {
    tx = 0.24;
    ty = 0.28;
  }
  scene.addEventListener('pointermove', pointer);
  scene.addEventListener('pointerleave', leave);
  document.addEventListener('visibilitychange', refresh);
  reduced.addEventListener('change', refresh);
  start();
  return {
    pause(value: boolean) {
      busy = value;
      scene.dataset['paused'] = String(value);
      refresh();
    },
    light(horizontal: number, vertical: number) {
      if (
        !destroyed &&
        !busy &&
        !reduced.matches &&
        Number.isFinite(horizontal) &&
        Number.isFinite(vertical)
      ) {
        tx = clamp(horizontal, 0.05, 0.95);
        ty = clamp(vertical, 0.05, 0.95);
      }
    },
    destroy() {
      destroyed = true;
      stop();
      observer.disconnect();
      scene.removeEventListener('pointermove', pointer);
      scene.removeEventListener('pointerleave', leave);
      document.removeEventListener('visibilitychange', refresh);
      reduced.removeEventListener('change', refresh);
      material.width = material.height = 0;
    },
  };
}
