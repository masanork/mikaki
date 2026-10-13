<script lang="ts">
  import * as m from './paraglide/messages.js';
  let { current }: { current: 1 | 2 | 3 } = $props();
  const labels = $derived([m.work_step_select(), m.work_step_review(), m.work_step_copy()]);
</script>

<ol class="work-steps" aria-label={m.work_steps()}>
  {#each labels as label, i}
    <li aria-current={current === i + 1 ? 'step' : undefined} class:completed={current > i + 1}>
      <span class="work-step-number" aria-hidden="true">{i + 1}</span><span>{label}</span>
    </li>
  {/each}
</ol>
