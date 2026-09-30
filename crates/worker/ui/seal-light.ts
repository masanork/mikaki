// Decorative only: no credentials, browser fingerprinting, or pointer tracking.
export function createSealLight(
  canvas: HTMLCanvasElement,
  state: () => { phase: number; paused: boolean },
  active: (value: boolean) => void,
): { refresh: () => void; dispose: () => void } {
  const motion = matchMedia('(prefers-reduced-motion: reduce)');
  const desktop = matchMedia('(min-width: 761px)');
  let gl: WebGLRenderingContext | null = null;
  let program: WebGLProgram | null = null;
  let buffer: WebGLBuffer | null = null;
  let frame = 0;
  let last = 0;
  let elapsed = 0;
  let disposed = false;
  let lost = false;
  let failed = false;
  let timeUniform: WebGLUniformLocation | null = null;
  let phaseUniform: WebGLUniformLocation | null = null;

  function initialize(): boolean {
    if (gl) return true;
    gl = canvas.getContext('webgl', {
      alpha: true,
      antialias: false,
      depth: false,
      stencil: false,
      preserveDrawingBuffer: false,
      premultipliedAlpha: false,
      powerPreference: 'low-power',
    });
    if (!gl) return false;
    const context = gl;
    const shaders: WebGLShader[] = [];
    try {
      program = context.createProgram();
      if (!program) throw new Error('No decorative program');
      for (const [type, source] of [
        [
          context.VERTEX_SHADER,
          'attribute vec2 position; varying vec2 uv; void main(){ uv=position; gl_Position=vec4(position,0.,1.); }',
        ],
        [
          context.FRAGMENT_SHADER,
          `precision mediump float;
          varying vec2 uv; uniform float time; uniform float phase;
          void main(){
            float r=length(uv); float a=atan(uv.y,uv.x);
            float band=exp(-pow((r-.66)/.20,2.));
            float shimmer=.5+.5*sin(a*3.+r*13.-time*.24+phase*6.283);
            vec3 ink=mix(vec3(.12,.44,.82),vec3(.40,.94,.86),shimmer);
            float sheen=pow(.5+.5*cos(a-time*.09+phase*6.283),8.);
            gl_FragColor=vec4(ink,band*(.12+.42*sheen));
          }`,
        ],
      ] as const) {
        const shader = context.createShader(type);
        if (!shader) throw new Error('No decorative shader');
        shaders.push(shader);
        context.shaderSource(shader, source);
        context.compileShader(shader);
        if (!context.getShaderParameter(shader, context.COMPILE_STATUS))
          throw new Error('Decorative shader unavailable');
        context.attachShader(program, shader);
      }
      context.linkProgram(program);
      if (!context.getProgramParameter(program, context.LINK_STATUS))
        throw new Error('Decorative program unavailable');
      context.useProgram(program);
      buffer = context.createBuffer();
      if (!buffer) throw new Error('No decorative buffer');
      context.bindBuffer(context.ARRAY_BUFFER, buffer);
      context.bufferData(
        context.ARRAY_BUFFER,
        new Float32Array([-1, -1, 1, -1, -1, 1, -1, 1, 1, -1, 1, 1]),
        context.STATIC_DRAW,
      );
      const position = context.getAttribLocation(program, 'position');
      context.enableVertexAttribArray(position);
      context.vertexAttribPointer(position, 2, context.FLOAT, false, 0, 0);
      timeUniform = context.getUniformLocation(program, 'time');
      phaseUniform = context.getUniformLocation(program, 'phase');
      return true;
    } finally {
      for (const shader of shaders) context.deleteShader(shader);
    }
  }

  function draw(): void {
    if (!gl || lost || disposed) return;
    const size = Math.min(
      720,
      Math.round(canvas.getBoundingClientRect().width * Math.min(devicePixelRatio, 1.5)),
    );
    if (size < 1) return;
    if (canvas.width !== size || canvas.height !== size) {
      canvas.width = size;
      canvas.height = size;
    }
    gl.viewport(0, 0, size, size);
    gl.uniform1f(timeUniform, elapsed);
    gl.uniform1f(phaseUniform, state().phase);
    gl.drawArrays(gl.TRIANGLES, 0, 6);
  }
  function tick(now: number): void {
    if (last === 0) last = now;
    if (now - last >= 1000 / 30) {
      elapsed += Math.min((now - last) / 1000, 0.1);
      last = now;
      draw();
    }
    frame = requestAnimationFrame(tick);
  }
  function refresh(): void {
    cancelAnimationFrame(frame);
    frame = 0;
    last = 0;
    if (disposed || lost || failed || motion.matches || !desktop.matches || document.hidden) {
      active(false);
      return;
    }
    try {
      if (!initialize()) {
        failed = true;
        active(false);
        return;
      }
      active(true);
      draw();
      if (!state().paused) frame = requestAnimationFrame(tick);
    } catch {
      failed = true;
      active(false);
      release();
    }
  }
  function release(): void {
    if (gl && !lost) {
      gl.deleteBuffer(buffer);
      gl.deleteProgram(program);
    }
    buffer = null;
    program = null;
  }
  function contextLost(): void {
    lost = true;
    refresh(); // Keep the SVG; do not repeatedly allocate a failing GPU context.
  }
  canvas.addEventListener('webglcontextlost', contextLost);
  motion.addEventListener('change', refresh);
  desktop.addEventListener('change', refresh);
  document.addEventListener('visibilitychange', refresh);
  const resize = new ResizeObserver(refresh);
  resize.observe(canvas);
  refresh();
  return {
    refresh,
    dispose() {
      disposed = true;
      cancelAnimationFrame(frame);
      resize.disconnect();
      canvas.removeEventListener('webglcontextlost', contextLost);
      motion.removeEventListener('change', refresh);
      desktop.removeEventListener('change', refresh);
      document.removeEventListener('visibilitychange', refresh);
      release();
    },
  };
}
