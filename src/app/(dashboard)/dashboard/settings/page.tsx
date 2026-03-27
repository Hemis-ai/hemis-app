export default function SettingsPage() {
  return (
    <div style={{ padding: '28px 28px 40px' }}>
      <div style={{ marginBottom: 24 }}>
        <h1 className="display" style={{ fontSize: 22, fontWeight: 700, color: 'var(--color-text-primary)', margin: 0 }}>
          Settings
        </h1>
        <p style={{ fontSize: 13, color: 'var(--color-text-secondary)', margin: '4px 0 0' }}>
          Workspace configuration and preferences
        </p>
      </div>

      <div style={{
        background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)',
        padding: '32px 28px', borderRadius: 4, maxWidth: 520,
        display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12,
        textAlign: 'center',
      }}>
        <div style={{ fontSize: 32 }}>⚙</div>
        <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--color-text-primary)' }}>Settings Coming Soon</div>
        <div style={{ fontSize: 13, color: 'var(--color-text-secondary)', lineHeight: 1.6 }}>
          Account preferences, integrations, billing, and team management will be available here.
        </div>
      </div>
    </div>
  )
}
