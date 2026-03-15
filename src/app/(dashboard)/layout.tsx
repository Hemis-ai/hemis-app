import Sidebar from '@/components/layout/sidebar'
import Topbar  from '@/components/layout/topbar'

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ display:'flex', minHeight:'100vh', background:'var(--color-bg-base)', color:'var(--color-text-primary)' }}>
      <Sidebar />
      <div style={{ flex:1, display:'flex', flexDirection:'column', minWidth:0, overflow:'hidden' }}>
        <Topbar />
        <main style={{ flex:1, overflow:'auto' }}>
          {children}
        </main>
      </div>
    </div>
  )
}
