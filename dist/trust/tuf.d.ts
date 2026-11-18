import { TrustedRoot } from "../interfaces.js";
/**
 * Options for TrustedRootProvider configuration
 */
export interface TrustedRootProviderOptions {
    /**
     * TUF repository URL for metadata
     * Default: Sigstore production TUF repository
     */
    metadataUrl?: string;
    /**
     * Target base URL for fetching target files
     * If not specified, uses the same as metadataUrl
     */
    targetBaseUrl?: string;
    /**
     * Initial root metadata (1.root.json content)
     * If not provided, will use embedded default
     */
    initialRoot?: string;
    /**
     * Namespace for TUF cache storage
     * Default: 'tuf-cache'
     */
    namespace?: string;
    /**
     * Name of the trusted root target file
     * Default: 'trusted_root.json'
     */
    trustedRootTarget?: string;
    /**
     * Cache TTL in milliseconds
     * Default: 1 hour (3600000 ms)
     */
    cacheTTL?: number;
    /**
     * Disable persistent caching (use in-memory only)
     * Default: false
     */
    disableCache?: boolean;
}
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
export declare class TrustedRootProvider {
    private metadataUrl;
    private targetBaseUrl?;
    private initialRoot?;
    private namespace;
    private trustedRootTarget;
    private cacheTTL;
    private disableCache;
    private tufClient?;
    private cachedRoot?;
    private cacheTimestamp?;
    constructor(options?: TrustedRootProviderOptions);
    /**
     * Initialize the TUF client
     * Lazy initialization to avoid loading TUF client until needed
     */
    private initTUFClient;
    /**
     * Get the default embedded root metadata
     * Returns the TUF root.json that bootstraps the TUF client
     */
    private getDefaultRoot;
    /**
     * Check if cached trusted root is still valid
     */
    private isCacheValid;
    /**
     * Get the Sigstore trusted root metadata
     * Uses TUF to securely fetch and verify the trusted root
     *
     * @returns Promise<TrustedRoot> The verified trusted root metadata
     * @throws Error if TUF verification fails or root cannot be fetched
     */
    getTrustedRoot(): Promise<TrustedRoot>;
    /**
     * Manually refresh the trusted root from TUF
     * Bypasses cache and forces a fresh fetch
     *
     * @returns Promise<TrustedRoot> The updated trusted root metadata
     */
    refreshTrustedRoot(): Promise<TrustedRoot>;
    /**
     * Clear the cached trusted root
     * Next call to getTrustedRoot() will fetch fresh data
     */
    clearCache(): void;
}
