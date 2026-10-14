<script lang="ts">
  import { tick } from 'svelte';
  import * as m from './paraglide/messages.js';
  let step = $state(1),
    goal = $state(''),
    acceptance = $state('');
  let reference = $state(true),
    acknowledged = $state(false),
    adopted = $state(false);
  let heading: HTMLHeadingElement | undefined = $state();
  const labels = $derived([
    m.work_journey_request(),
    m.work_journey_materials(),
    m.work_journey_activity(),
    m.work_journey_result(),
  ]);
  async function advance(next: number) {
    step = next;
    acknowledged = false;
    adopted = false;
    await tick();
    heading?.focus();
  }
  function example() {
    goal = m.work_demo_goal_example();
    acceptance = m.work_demo_acceptance_example();
  }
</script>

<section id="work-journey-demo" class="journey-demo" aria-label={m.work_demo_title()}>
  <div class="demo-caption">
    <strong>{m.work_demo_badge()}</strong><span>{m.work_demo_boundary()}</span>
  </div>
  <ol class="demo-steps" aria-label={m.work_demo_steps()}>
    {#each labels as label, i}<li
        aria-current={step === i + 1 ? 'step' : undefined}
        class:done={step > i + 1}
      >
        <span>{i + 1}</span>{label}
      </li>{/each}
  </ol>
  <h3 bind:this={heading} tabindex="-1">{labels[step - 1]}</h3>
  {#if step === 1}
    <p>{m.work_demo_request_intro()}</p>
    <button type="button" class="example-button" onclick={example}
      >{m.work_demo_use_example()}</button
    >
    <form
      onsubmit={(event) => {
        event.preventDefault();
        if (goal.trim() && acceptance.trim()) void advance(2);
      }}
    >
      <label
        >{m.work_demo_goal()}<textarea
          rows="3"
          maxlength="500"
          required
          bind:value={goal}
          placeholder={m.work_demo_goal_example()}></textarea></label
      >
      <label
        >{m.work_demo_acceptance()}<textarea
          rows="2"
          maxlength="500"
          required
          bind:value={acceptance}
          placeholder={m.work_demo_acceptance_example()}></textarea></label
      >
      <button class="work-primary" type="submit" disabled={!goal.trim() || !acceptance.trim()}
        >{m.work_demo_choose_materials()}</button
      >
    </form>
  {:else if step === 2}
    <div class="request-summary">
      <strong>{goal}</strong>
      <p>{acceptance}</p>
    </div>
    <div class="material-card">
      <strong>sample-login</strong>
      <p>{m.work_demo_code_description()}</p>
      <code>src/login.css · src/Login.svelte</code>
    </div>
    <label class="reference-choice"
      ><input type="checkbox" bind:checked={reference} /><span
        ><strong>design.md</strong><small>{m.work_demo_reference_description()}</small></span
      ></label
    >
    <div class="permission-summary">
      <strong>{m.work_demo_access_title()}</strong>
      <p>{m.work_demo_access()}</p>
    </div>
    <label class="reference-choice"
      ><input type="checkbox" bind:checked={acknowledged} />{m.work_demo_acknowledge()}</label
    >
    <div class="demo-actions">
      <button type="button" onclick={() => advance(1)}>{m.work_demo_edit_request()}</button><button
        type="button"
        class="work-primary"
        disabled={!acknowledged}
        onclick={() => advance(3)}>{m.work_demo_start()}</button
      >
    </div>
  {:else if step === 3}
    <div class="request-summary">
      <strong>{goal}</strong>
      <p>{acceptance}</p>
    </div>
    <p>{m.work_demo_activity_intro()}</p>
    <ol class="activity-list">
      <li>
        <strong>{m.work_demo_activity_copy()}</strong><span
          >{reference
            ? m.work_demo_activity_with_reference()
            : m.work_demo_activity_code_only()}</span
        >
      </li>
      <li>
        <strong>{m.work_demo_activity_change()}</strong><span
          >{m.work_demo_activity_change_detail()}</span
        >
      </li>
      <li>
        <strong>{m.work_demo_activity_check()}</strong><span
          >{m.work_demo_activity_check_detail()}</span
        >
      </li>
    </ol>
    <button type="button" class="work-primary" onclick={() => advance(4)}
      >{m.work_demo_show_result()}</button
    >
  {:else}
    <div class="request-summary">
      <strong>{goal}</strong>
      <p>{acceptance}</p>
    </div>
    <p>{m.work_demo_result_intro()}</p>
    <div class="diff-heading">
      <strong>src/login.css</strong><span>{m.work_demo_diff_summary()}</span>
    </div>
    <pre class="sample-diff" aria-label={m.work_demo_diff_label()}><code
        ><span class="removed">{'- .login-actions { width: 420px; }'}</span>{'\n'}<span
          class="added">{'+ .login-actions { width: 100%; max-width: 420px; }'}</span
        >{'\n'}<span class="added">{'+ .login-actions button { max-width: 100%; }'}</span></code
      ></pre>
    <p class="check-result">{m.work_demo_check_result()}</p>
    {#if adopted}<p role="status" class="adoption-result">{m.work_demo_adopted()}</p>{:else}<button
        type="button"
        class="work-primary"
        onclick={() => (adopted = true)}>{m.work_demo_adopt()}</button
      >{/if}
    <div class="demo-actions">
      <button type="button" onclick={() => advance(1)}>{m.work_demo_restart()}</button>
    </div>
  {/if}
</section>

<style>
  .journey-demo {
    margin-top: 1.5rem;
    padding-top: 1.5rem;
    border-top: 1px solid #cbd7d2;
  }
  .demo-caption {
    display: flex;
    align-items: baseline;
    flex-wrap: wrap;
    gap: 0.6rem;
    font-size: 0.8rem;
    color: #53645d;
  }
  .demo-caption strong {
    padding: 0.25rem 0.6rem;
    border: 1px solid #9caea4;
    border-radius: 2rem;
    color: #294637;
  }
  .demo-steps {
    display: flex;
    flex-wrap: wrap;
    gap: 0.7rem 1.1rem;
    padding: 0;
    margin: 1.4rem 0;
    list-style: none;
    font-size: 0.85rem;
    color: #62716a;
  }
  .demo-steps li {
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }
  .demo-steps li span {
    display: grid;
    place-items: center;
    width: 1.6rem;
    height: 1.6rem;
    border: 1px solid #aab9b0;
    border-radius: 50%;
  }
  .demo-steps [aria-current='step'] {
    color: #233f30;
    font-weight: 700;
  }
  .demo-steps [aria-current='step'] span {
    background: #294c39;
    color: white;
  }
  h3 {
    font-size: 1.35rem;
  }
  form {
    display: grid;
    gap: 1.1rem;
    margin-top: 1rem;
  }
  form label {
    display: grid;
    gap: 0.5rem;
    font-weight: 600;
  }
  textarea {
    width: 100%;
    box-sizing: border-box;
    resize: vertical;
    font: inherit;
    line-height: 1.6;
    padding: 0.75rem;
    border: 1px solid #aab9b0;
    border-radius: 0.5rem;
    background: white;
    color: #243c30;
  }
  .example-button {
    font-size: 0.85rem;
  }
  .request-summary {
    padding: 1rem;
    border-left: 3px solid #557b62;
    background: white;
    margin: 1rem 0;
    overflow-wrap: anywhere;
  }
  .request-summary p {
    margin-bottom: 0;
    font-size: 0.9rem;
  }
  .material-card,
  .permission-summary {
    border: 1px solid #cbd7d2;
    padding: 1rem;
    border-radius: 0.6rem;
    margin: 1rem 0;
  }
  .material-card p,
  .permission-summary p {
    font-size: 0.9rem;
  }
  .material-card code {
    font-size: 0.8rem;
    overflow-wrap: anywhere;
  }
  .reference-choice {
    display: flex;
    align-items: flex-start;
    gap: 0.65rem;
    margin: 1rem 0;
    line-height: 1.6;
  }
  .reference-choice input {
    flex: 0 0 auto;
    margin-top: 0.3rem;
  }
  .reference-choice small {
    display: block;
    color: #586b60;
  }
  .demo-actions {
    display: flex;
    gap: 0.75rem;
    flex-wrap: wrap;
    margin: 1rem 0;
  }
  .activity-list {
    padding-left: 1.3rem;
  }
  .activity-list li {
    margin: 1rem 0;
  }
  .activity-list span {
    display: block;
    color: #586b60;
    font-size: 0.9rem;
    margin-top: 0.25rem;
  }
  .diff-heading {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem 1rem;
    margin: 1.2rem 0 0.5rem;
    font-size: 0.85rem;
  }
  .sample-diff {
    max-width: 100%;
    overflow-x: auto;
    background: white;
    padding: 1rem;
    border: 1px solid #cbd7d2;
    border-radius: 0.5rem;
    font-size: 0.8rem;
    line-height: 1.8;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  .removed {
    background: #fae5e1;
    color: #773325;
  }
  .added {
    background: #e3f0e2;
    color: #25472e;
  }
  .check-result,
  .adoption-result {
    padding: 0.8rem 1rem;
    background: #e3eee3;
    border-radius: 0.5rem;
    font-size: 0.9rem;
  }
</style>
