let PrismaClientConstructor: any

try {
  // Dynamic import to avoid build failure when @prisma/client isn't generated
  PrismaClientConstructor = require('@prisma/client').PrismaClient
} catch {
  PrismaClientConstructor = null
}

// Prevent multiple instances during hot reload in development
const globalForPrisma = globalThis as unknown as {
  prisma: any | undefined
}

export const prisma: any =
  PrismaClientConstructor
    ? (globalForPrisma.prisma ??
      new PrismaClientConstructor({
        log: process.env.NODE_ENV === 'development'
          ? ['error', 'warn']
          : ['error'],
      }))
    : null

if (process.env.NODE_ENV !== 'production' && prisma) {
  globalForPrisma.prisma = prisma
}

/**
 * Check if the database is reachable. Used for demo-mode fallback.
 */
export async function isDatabaseReachable(): Promise<boolean> {
  if (!prisma) return false
  try {
    await prisma.$queryRaw`SELECT 1`
    return true
  } catch {
    return false
  }
}
