declare namespace Cloudflare {
  interface Env {
    DB?: D1Database;
    BUCKET?: R2Bucket;
    VEIL_SETUP_HASH?: string;
  }
}
