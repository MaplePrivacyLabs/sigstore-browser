/*
 * TUF (The Update Framework) integration for trusted root management
 *
 * Provides secure updates for Sigstore trusted root metadata using TUF.
 * Uses tuf-browser for browser-compatible TUF client functionality.
 *
 * Reference: https://github.com/freedomofpress/tuf-browser
 */
import { base64Decode, Uint8ArrayToString } from "@freedomofpress/crypto-browser";
/**
 * Default configuration for Sigstore production TUF repository
 */
const DEFAULT_CONFIG = {
    metadataUrl: 'https://tuf-repo-cdn.sigstore.dev/',
    targetBaseUrl: 'https://tuf-repo-cdn.sigstore.dev/targets/',
    namespace: 'tuf-cache',
    trustedRootTarget: 'trusted_root.json',
    cacheTTL: 3600000, // 1 hour
};
/**
 * Provides Sigstore trusted root via TUF for secure updates
 *
 * This class manages fetching and caching of Sigstore trusted root metadata
 * using The Update Framework (TUF) for secure, verified updates.
 *
 * Example usage:
 * ```typescript
 * const provider = new TrustedRootProvider();
 * const trustedRoot = await provider.getTrustedRoot();
 * ```
 */
export class TrustedRootProvider {
    constructor(options = {}) {
        const metadataUrl = options.metadataUrl || DEFAULT_CONFIG.metadataUrl;
        this.metadataUrl = metadataUrl.endsWith('/') ? metadataUrl : `${metadataUrl}/`;
        const targetBaseUrl = options.targetBaseUrl || DEFAULT_CONFIG.targetBaseUrl;
        this.targetBaseUrl = targetBaseUrl.endsWith('/') ? targetBaseUrl : `${targetBaseUrl}/`;
        this.initialRoot = options.initialRoot;
        this.namespace = options.namespace || DEFAULT_CONFIG.namespace;
        this.trustedRootTarget = options.trustedRootTarget || DEFAULT_CONFIG.trustedRootTarget;
        this.cacheTTL = options.cacheTTL ?? DEFAULT_CONFIG.cacheTTL;
        this.disableCache = options.disableCache ?? false;
    }
    /**
     * Initialize the TUF client
     * Lazy initialization to avoid loading TUF client until needed
     */
    async initTUFClient() {
        if (this.tufClient) {
            return;
        }
        try {
            const { TUFClient } = await import('@freedomofpress/tuf-browser');
            // Get initial root metadata
            const rootMetadata = this.initialRoot || await this.getDefaultRoot();
            this.tufClient = new TUFClient(this.metadataUrl, rootMetadata, this.namespace, this.targetBaseUrl, { disableCache: this.disableCache });
        }
        catch (error) {
            throw new Error(`Failed to initialize TUF client: ${error instanceof Error ? error.message : String(error)}`);
        }
    }
    /**
     * Get the default embedded root metadata
     * Returns the TUF root.json that bootstraps the TUF client
     */
    async getDefaultRoot() {
        // Import the embedded TUF root metadata (base64-encoded 1.root.json as string)
        // This is the root of trust for TUF, not to be confused with the Sigstore trusted root
        const { default: tufRootBase64 } = await import('./tuf-root.js');
        return base64Decode(tufRootBase64);
    }
    /**
     * Check if cached trusted root is still valid
     */
    isCacheValid() {
        if (!this.cachedRoot || !this.cacheTimestamp) {
            return false;
        }
        const now = Date.now();
        return (now - this.cacheTimestamp) < this.cacheTTL;
    }
    /**
     * Get the Sigstore trusted root metadata
     * Uses TUF to securely fetch and verify the trusted root
     *
     * @returns Promise<TrustedRoot> The verified trusted root metadata
     * @throws Error if TUF verification fails or root cannot be fetched
     */
    async getTrustedRoot() {
        // Return cached root if still valid
        if (this.isCacheValid() && this.cachedRoot) {
            return this.cachedRoot;
        }
        // Initialize TUF client if needed
        await this.initTUFClient();
        if (!this.tufClient) {
            throw new Error('TUF client not initialized');
        }
        try {
            // Update TUF metadata (root, timestamp, snapshot, targets)
            // This must be called before getTarget() to populate the metadata cache
            await this.tufClient.updateTUF();
            // Fetch the trusted root target via TUF
            // TUF will handle all verification (signatures, rollback protection, etc.)
            const trustedRootBuffer = await this.tufClient.getTarget(this.trustedRootTarget);
            // Parse the trusted root JSON
            const trustedRootJson = Uint8ArrayToString(new Uint8Array(trustedRootBuffer));
            const trustedRoot = JSON.parse(trustedRootJson);
            // Cache the result
            this.cachedRoot = trustedRoot;
            this.cacheTimestamp = Date.now();
            return trustedRoot;
        }
        catch (error) {
            throw new Error(`Failed to fetch trusted root via TUF: ${error instanceof Error ? error.message : String(error)}`);
        }
    }
    /**
     * Manually refresh the trusted root from TUF
     * Bypasses cache and forces a fresh fetch
     *
     * @returns Promise<TrustedRoot> The updated trusted root metadata
     */
    async refreshTrustedRoot() {
        // Clear cache
        this.cachedRoot = undefined;
        this.cacheTimestamp = undefined;
        // Fetch fresh root
        return await this.getTrustedRoot();
    }
    /**
     * Clear the cached trusted root
     * Next call to getTrustedRoot() will fetch fresh data
     */
    clearCache() {
        this.cachedRoot = undefined;
        this.cacheTimestamp = undefined;
    }
}
//# sourceMappingURL=tuf.js.map