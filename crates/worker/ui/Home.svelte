<script lang="ts">
  import * as m from './paraglide/messages.js';
  import { switchLocale } from './locale.js';
  import WovenGate from './WovenGate.svelte';
  import { weaveProfile } from './woven-gate.js';

  let { locale }: { locale: 'ja' | 'en' } = $props();
  const page = new URL(location.href);
  const profile = weaveProfile(page.origin);
</script>

<div class="auth-shell home-shell" style={`--page-hue:${profile.hue};--rp-hue:${profile.hue}`}>
  <div class="shade" aria-hidden="true"></div>
  <div class="plate home-plate">
    <div class="item home-name">mikaki</div>
    <div
      class="item origin"
      style={`--grain-step:${profile.spacing / 2}px;--grain-angle:${profile.grainAngle}deg`}
    >
      <span>{m.authOriginLabel()}</span><strong>{page.host}</strong>
    </div>
  </div>
  <main class="entry home-entry">
    <h1>{m.homeHeading()}</h1>
  </main>
  <footer>
    <a class="quiet home-enroll" href={`/enroll?lang=${locale}`}
      >{m.homeEnroll()}<span aria-hidden="true">↗</span></a
    >
    <WovenGate pageOrigin={page.origin} rpOrigin={page.origin} paused={false} layout="fence" />
    <select
      class="language"
      aria-label={m.language()}
      value={locale}
      onchange={(event) => switchLocale(event.currentTarget.value)}
    >
      <option value="ja">日本語</option><option value="en">English</option>
    </select>
  </footer>
</div>
