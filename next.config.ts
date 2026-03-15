import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  devIndicators: false,
  serverExternalPackages: ['pdfkit'],
  turbopack: {
    root: __dirname,
  },
};

export default nextConfig;
