/**
 * HemisX Database Seed
 * Run with: npm run db:seed
 *
 * Creates:
 *  - Demo Organization (HemisX Demo)
 *  - Demo Owner user  (demo@hemisx.com / demo1234)
 *  - Sample analyst   (analyst@hemisx.com / analyst1234)
 */

import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcryptjs'

const prisma = new PrismaClient()
const SALT_ROUNDS = 12

async function main() {
  console.log('🌱 Seeding HemisX database...')

  // ── Organization ──────────────────────────────────────────────────────────
  const org = await prisma.organization.upsert({
    where:  { slug: 'hemisx-demo' },
    update: {},
    create: {
      name: 'HemisX Demo Org',
      slug: 'hemisx-demo',
      plan: 'PROFESSIONAL',
    },
  })
  console.log(`  ✓ Organization: ${org.name} (${org.id})`)

  // ── Users ─────────────────────────────────────────────────────────────────
  const ownerHash   = await bcrypt.hash('demo1234',     SALT_ROUNDS)
  const analystHash = await bcrypt.hash('analyst1234',  SALT_ROUNDS)
  const adminHash   = await bcrypt.hash('admin1234',    SALT_ROUNDS)

  const owner = await prisma.user.upsert({
    where:  { email: 'demo@hemisx.com' },
    update: {},
    create: {
      email:        'demo@hemisx.com',
      name:         'Demo Owner',
      passwordHash: ownerHash,
      role:         'OWNER',
      orgId:        org.id,
    },
  })
  console.log(`  ✓ User (OWNER):   ${owner.email}`)

  const admin = await prisma.user.upsert({
    where:  { email: 'admin@hemisx.com' },
    update: {},
    create: {
      email:        'admin@hemisx.com',
      name:         'Admin User',
      passwordHash: adminHash,
      role:         'ADMIN',
      orgId:        org.id,
    },
  })
  console.log(`  ✓ User (ADMIN):   ${admin.email}`)

  const analyst = await prisma.user.upsert({
    where:  { email: 'analyst@hemisx.com' },
    update: {},
    create: {
      email:        'analyst@hemisx.com',
      name:         'Security Analyst',
      passwordHash: analystHash,
      role:         'ANALYST',
      orgId:        org.id,
    },
  })
  console.log(`  ✓ User (ANALYST): ${analyst.email}`)

  // ── Sample Red Team Scan ───────────────────────────────────────────────────
  const existingScan = await prisma.redTeamScan.findFirst({
    where: { orgId: org.id, engagementId: 'seed-engagement-01' },
  })

  if (!existingScan) {
    const scan = await prisma.redTeamScan.create({
      data: {
        orgId:        org.id,
        initiatedBy:  owner.id,
        engagementId: 'seed-engagement-01',
        target:       'https://demo.target.com',
        scope:        ['web_app', 'api'],
        status:       'COMPLETED',
        progress:     100,
        completedAt:  new Date(),
        findings: {
          create: [
            {
              type:              'sql_injection',
              severity:          'CRITICAL',
              cvssScore:         9.2,
              affectedComponent: 'POST /api/v1/login',
              description:       'SQL injection in login endpoint. User-supplied input concatenated directly into SQL query.',
              remediation:       'Use parameterized queries or prepared statements. Validate and sanitize all input.',
              proofOfConcept:    "' OR '1'='1",
              mitreId:           'T1190',
              status:            'OPEN',
            },
            {
              type:              'xss_vulnerability',
              severity:          'HIGH',
              cvssScore:         7.1,
              affectedComponent: 'POST /api/v1/feedback',
              description:       'Reflected XSS. User input echoed in HTML response without sanitization.',
              remediation:       'HTML-encode all output. Implement Content-Security-Policy headers.',
              proofOfConcept:    '<script>alert(document.domain)</script>',
              mitreId:           'T1059',
              status:            'OPEN',
            },
            {
              type:              'auth_bypass',
              severity:          'HIGH',
              cvssScore:         8.2,
              affectedComponent: 'JWT token validation',
              description:       'JWT "none" algorithm accepted by API — token signature not verified.',
              remediation:       'Reject tokens signed with "none" algorithm. Enforce HS256/RS256 verification.',
              proofOfConcept:    'alg=none in JWT header accepted',
              mitreId:           'T1078',
              status:            'OPEN',
            },
          ],
        },
      },
    })
    console.log(`  ✓ Red Team Scan:  ${scan.id} (3 findings)`)
  } else {
    console.log(`  ⟳ Red Team Scan already exists, skipping`)
  }

  console.log('\n✅ Seed complete!')
  console.log('\n── Demo credentials ─────────────────────────────────────────')
  console.log('   Owner:   demo@hemisx.com    / demo1234')
  console.log('   Admin:   admin@hemisx.com   / admin1234')
  console.log('   Analyst: analyst@hemisx.com / analyst1234')
  console.log('────────────────────────────────────────────────────────────\n')
}

main()
  .catch(e => { console.error(e); process.exit(1) })
  .finally(() => prisma.$disconnect())
