<script lang="ts">
  // Brahma sync: sign in to the same Brahma account as your other Brahma
  // apps, or paste a brahma:// link (pair with another device, or follow a
  // server that moved). Samriddhi shares only a short wealth summary and reads
  // only Artha's money summary; nothing else from other apps is kept.
  import { Button, Card } from '@samriddhi/ui'
  import { call, type SyncView } from '../lib/api.ts'
  import { toast } from '../lib/toast.svelte.ts'

  let view = $state<SyncView | null>(null)
  let server = $state('')
  let email = $state('')
  let password = $state('')
  let recovery = $state('')
  let link = $state('')
  let busy = $state(false)
  let poll: ReturnType<typeof setInterval> | null = null

  async function run(f: () => Promise<SyncView>, done?: string) {
    busy = true
    try {
      view = await f()
      if (done) toast.show(done)
    } catch (e) {
      toast.error(e)
    } finally {
      busy = false
      watchJoin()
    }
  }
  run(() => call('sync_status'))

  // While a join waits for the other device, ask every few seconds.
  function watchJoin() {
    if (view?.joinCode && !poll) {
      poll = setInterval(async () => {
        try {
          view = await call('sync_join_check')
        } catch (e) {
          toast.error(e)
          view = view ? { ...view, joinCode: null } : view
        }
        if (!view?.joinCode && poll) {
          clearInterval(poll)
          poll = null
        }
      }, 3000)
    }
  }
  $effect(() => () => {
    if (poll) clearInterval(poll)
  })

  function signIn(e: SubmitEvent) {
    e.preventDefault()
    const p = password
    password = ''
    run(() => call('sync_sign_in', { server: server.trim(), email: email.trim(), password: p }), 'Signed in.')
  }

  function unlock(e: SubmitEvent) {
    e.preventDefault()
    const k = recovery.trim()
    recovery = ''
    run(() => call('sync_recovery', { recoveryKey: k }), 'Synced data unlocked.')
  }

  async function useLink(e: SubmitEvent) {
    e.preventDefault()
    busy = true
    try {
      const done = await call('sync_link', { link: link.trim() })
      link = ''
      view = done.view
      if (done.kind === 'setup' && done.server) {
        server = done.server
        toast.show('Server filled in. Sign in with your Brahma account.')
      } else if (done.kind === 'moved') toast.show('Following your account to its new server.')
    } catch (e) {
      toast.error(e)
    } finally {
      busy = false
      watchJoin()
    }
  }
</script>

<div class="grid">
  <Card title="Brahma sync" explain="Sign in to the same Brahma account as your other Brahma apps. Everything is end-to-end encrypted: the server only sees scrambled data. The sign-in keys stay in this device's keyring (the Keystore on Android).">
    {#if !view}
      <p class="muted">Loading…</p>
    {:else if view.signedIn}
      <div class="stack">
        <p class="small">Signed in as <strong>{view.email}</strong> on <span class="num">{view.server}</span>.</p>
        <p class="muted small">{view.lastSync ? `Last synced ${view.lastSync.replace('T', ' ').slice(0, 16)} UTC.` : 'Not synced yet.'}</p>
        {#if view.lastError}<p class="note-box warn small">{view.lastError}</p>{/if}
        <div class="row-actions">
          <Button disabled={busy} onclick={() => run(() => call('sync_now'), 'Synced.')}>Sync now</Button>
          <Button variant="ghost" disabled={busy} onclick={() => run(() => call('sync_sign_out'), 'Signed out. Your own data stays here.')}>Sign out</Button>
        </div>
      </div>
    {:else if view.needsRecovery}
      <form class="stack" onsubmit={unlock}>
        <p class="small">Your password was reset, so your synced data needs your recovery key once.</p>
        <div class="field"><label for="sync-rk">Recovery key</label><input id="sync-rk" class="input num" autocomplete="off" spellcheck="false" bind:value={recovery} /></div>
        <div class="row-actions"><Button type="submit" disabled={busy || !recovery.trim()}>Unlock</Button></div>
      </form>
    {:else if view.joinCode}
      <div class="stack">
        <p class="small">Check this code matches the one on your other device, then approve it there.</p>
        <p class="code num" aria-label="Pairing code">{view.joinCode}</p>
        <div class="row-actions"><Button variant="ghost" onclick={() => run(async () => { await call('sync_cancel_join'); return call('sync_status') })}>Cancel</Button></div>
      </div>
    {:else}
      <form class="stack" onsubmit={signIn}>
        <div class="field"><label for="sync-server">Server</label><input id="sync-server" class="input num" autocomplete="off" spellcheck="false" placeholder="https://" bind:value={server} /></div>
        <div class="field"><label for="sync-email">E-mail</label><input id="sync-email" class="input" type="email" autocomplete="username" bind:value={email} /></div>
        <div class="field"><label for="sync-pw">Password</label><input id="sync-pw" class="input" type="password" autocomplete="current-password" bind:value={password} /></div>
        <div class="row-actions"><Button type="submit" disabled={busy || !server.trim() || !email.trim() || !password}>Sign in</Button></div>
      </form>
    {/if}
  </Card>

  {#if view && !view.joinCode && !view.needsRecovery}
    <div class="stack">
      <Card title="Use a Brahma link" explain="Paste a link from another Brahma app: a pairing link joins this device without typing your password, and a 'moved' link follows your account to its new server.">
        <form class="stack" onsubmit={useLink}>
          <div class="field"><label for="sync-link">Link</label><input id="sync-link" class="input num" autocomplete="off" spellcheck="false" placeholder="brahma://" bind:value={link} /></div>
          <div class="row-actions"><Button type="submit" variant="quiet" disabled={busy || !link.trim()}>Use link</Button></div>
        </form>
      </Card>
      <Card title="What is shared" explain="Only these two summaries travel; Samriddhi ignores every other app's data.">
        <ul class="small">
          <li><strong>Sent:</strong> your holdings in short (totals by kind of asset), net worth by month and exposure totals.</li>
          <li><strong>Read only:</strong> Artha's money summary (cash, debts, monthly spend), shown on the Wealth screen.</li>
        </ul>
      </Card>
    </div>
  {/if}
</div>

<style>
  .code { font-size: var(--text-title, 1.5rem); letter-spacing: 0.1em; margin: 0; }
</style>
