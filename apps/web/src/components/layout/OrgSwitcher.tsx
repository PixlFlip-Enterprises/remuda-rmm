import { useState, useEffect, useRef } from 'react';
import {
  Building2,
  ChevronDown,
  ChevronRight,
  Globe,
  MapPin,
  Check,
  Loader2
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useOrgStore, type Organization, type Site } from '@/stores/orgStore';
import { waitForPendingRefresh } from '@/stores/auth';

/**
 * When switching organizations, certain detail-view routes show data scoped to
 * the previous org and would render blank or 404 under the new org. For those
 * routes we navigate up to the list view in the destination org instead of
 * reloading the now-inaccessible URL.
 *
 * Returns the destination URL when redirection is needed, otherwise null
 * (meaning the caller should keep the current path and just reload).
 */
export function getOrgSwitchRedirect(pathname: string): string | null {
  // /devices/:id -> /devices (but not /devices, /devices/compare, /devices/groups, etc.)
  const deviceDetail = pathname.match(/^\/devices\/([^/]+)\/?$/);
  if (deviceDetail) {
    const segment = deviceDetail[1];
    // Preserve sibling routes that share the prefix.
    if (segment !== 'compare' && segment !== 'groups') {
      return '/devices';
    }
  }
  return null;
}

const statusColors: Record<string, string> = {
  active: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300',
  trial: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300',
  suspended: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300',
  inactive: 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300'
};

function StatusBadge({ status }: { status: string }) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium capitalize',
        statusColors[status] || statusColors.inactive
      )}
    >
      {status}
    </span>
  );
}

function OrgMenuItem({
  org,
  isSelected,
  onSelect,
  sites,
  currentSiteId,
  onSelectSite
}: {
  org: Organization;
  isSelected: boolean;
  onSelect: () => void;
  sites: Site[];
  currentSiteId: string | null;
  onSelectSite: (siteId: string | null) => void;
}) {
  const [showSites, setShowSites] = useState(false);
  const orgSites = sites.filter((site) => site.orgId === org.id);
  const hasSites = orgSites.length > 0;

  return (
    <div className="relative">
      <button
        onClick={() => {
          onSelect();
          if (hasSites) {
            setShowSites(!showSites);
          }
        }}
        className={cn(
          'flex w-full items-center justify-between gap-2 rounded-md px-2 py-2 text-sm hover:bg-muted',
          isSelected && 'bg-muted'
        )}
      >
        <div className="flex items-center gap-2">
          <Building2 className="h-4 w-4 text-muted-foreground" />
          <span className="font-medium">{org.name}</span>
          {isSelected && <Check className="h-4 w-4 text-primary" />}
        </div>
        <div className="flex items-center gap-2">
          <StatusBadge status={org.status} />
          {hasSites && (
            <ChevronRight
              className={cn(
                'h-4 w-4 text-muted-foreground transition-transform',
                showSites && 'rotate-90'
              )}
            />
          )}
        </div>
      </button>

      {/* Sites submenu */}
      {showSites && hasSites && (
        <div className="ml-6 mt-1 border-l pl-2">
          <button
            onClick={() => onSelectSite(null)}
            className={cn(
              'flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-sm hover:bg-muted',
              currentSiteId === null && isSelected && 'bg-muted'
            )}
          >
            <span className="text-muted-foreground">All Sites</span>
            {currentSiteId === null && isSelected && (
              <Check className="h-3 w-3 text-primary" />
            )}
          </button>
          {orgSites.map((site) => (
            <button
              key={site.id}
              onClick={() => onSelectSite(site.id)}
              className={cn(
                'flex w-full items-center justify-between gap-2 rounded-md px-2 py-1.5 text-sm hover:bg-muted',
                currentSiteId === site.id && 'bg-muted'
              )}
            >
              <div className="flex items-center gap-2">
                <MapPin className="h-3 w-3 text-muted-foreground" />
                <span>{site.name}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-muted-foreground">
                  {site.deviceCount} devices
                </span>
                {currentSiteId === site.id && (
                  <Check className="h-3 w-3 text-primary" />
                )}
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

/**
 * Pill toggle that flips the global org scope. Sits to the LEFT of the org
 * picker. When in `all`, the picker is dimmed (still selectable for future
 * narrowing) and every fetchWithAuth call goes out without orgId injection
 * — server returns data across every accessible org.
 *
 * Hidden when the user has access to only one org (toggle would be a no-op).
 */
function OrgScopePill() {
  const orgScope = useOrgStore((s) => s.orgScope);
  const setOrgScope = useOrgStore((s) => s.setOrgScope);
  const organizationsCount = useOrgStore((s) => s.organizations.length);

  // Flipping the scope changes the orgId-injection chokepoint in orgStore, but
  // only pages with `orgScope` in their fetch deps refetch live. Rather than
  // rely on every list page opting in (easy to miss one), reload after the flip
  // so the new scope takes effect everywhere immediately — mirroring the
  // org-switch path. Skip the reload when the active scope is re-clicked (#989).
  const applyScope = async (next: 'current' | 'all') => {
    if (next === orgScope) return;
    setOrgScope(next);
    await waitForPendingRefresh();
    window.location.reload();
  };

  if (organizationsCount <= 1) return null;

  return (
    <div
      role="group"
      aria-label="Organization scope"
      data-testid="org-scope-pill"
      className="inline-flex overflow-hidden rounded-md border text-xs"
    >
      <button
        type="button"
        data-testid="org-scope-current"
        onClick={() => void applyScope('current')}
        aria-pressed={orgScope === 'current'}
        className={cn(
          'flex items-center gap-1 px-2 py-1.5 transition-colors',
          orgScope === 'current'
            ? 'bg-primary text-primary-foreground'
            : 'hover:bg-muted'
        )}
        title="Show data for the currently selected organization only"
      >
        <Building2 className="h-3 w-3" />
        Current
      </button>
      <button
        type="button"
        data-testid="org-scope-all"
        onClick={() => void applyScope('all')}
        aria-pressed={orgScope === 'all'}
        className={cn(
          'flex items-center gap-1 px-2 py-1.5 transition-colors',
          orgScope === 'all'
            ? 'bg-primary text-primary-foreground'
            : 'hover:bg-muted'
        )}
        title="Show data across every accessible organization"
      >
        <Globe className="h-3 w-3" />
        All orgs
      </button>
    </div>
  );
}

export default function OrgSwitcher() {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const {
    currentOrgId,
    currentSiteId,
    orgScope,
    organizations,
    sites,
    isLoading,
    setOrganization,
    setSite,
    fetchOrganizations,
    fetchSites
  } = useOrgStore();

  // Fetch data on mount
  useEffect(() => {
    fetchOrganizations();
  }, [fetchOrganizations]);

  // Fetch sites when org changes
  useEffect(() => {
    if (currentOrgId) {
      fetchSites();
    }
  }, [currentOrgId, fetchSites]);

  // Close dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Keyboard shortcut: Cmd+O to toggle org switcher
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'o') {
        e.preventDefault();
        setIsOpen((prev) => !prev);
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, []);

  // Get current selections
  const currentOrg = organizations.find((org) => org.id === currentOrgId);
  const currentSite = sites.find((site) => site.id === currentSiteId);

  // Build display text. In All-orgs scope the picker shows the partner-wide
  // label so the user can never be confused about which mode they're in.
  const displayText = orgScope === 'all'
    ? 'All organizations'
    : currentOrg
      ? currentSite
        ? `${currentOrg.name} / ${currentSite.name}`
        : currentOrg.name
      : 'Select Organization';

  return (
    <div className="flex items-center gap-2">
      <OrgScopePill />
      <div className="relative" ref={dropdownRef}>
        <button
          data-testid="org-switcher-trigger"
          onClick={() => setIsOpen(!isOpen)}
          className={cn(
            'flex items-center gap-2 rounded-md border px-3 py-1.5 text-sm hover:bg-muted',
            // Visually de-emphasize the picker when scope is All — the user
            // can still drill into a specific org via the dropdown, but the
            // picker is no longer the load-bearing scope control.
            orgScope === 'all' && 'opacity-70'
          )}
          disabled={isLoading}
          title={orgScope === 'all'
            ? 'Showing all organizations. Click to narrow to a specific org.'
            : 'Select Organization (Cmd+O)'}
        >
          {isLoading ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : orgScope === 'all' ? (
            <Globe className="h-4 w-4" />
          ) : (
            <Building2 className="h-4 w-4" />
          )}
          <span className="max-w-[200px] truncate">{displayText}</span>
          {orgScope === 'current' && currentOrg && <StatusBadge status={currentOrg.status} />}
          <ChevronDown
            className={cn(
              'h-4 w-4 text-muted-foreground transition-transform',
              isOpen && 'rotate-180'
            )}
          />
        </button>

      {isOpen && (
        <div className="absolute left-0 top-full z-50 mt-1 w-80 rounded-md border bg-popover p-2 shadow-lg">
          <div className="px-2 py-1.5 text-xs font-medium text-muted-foreground">
            Organizations
          </div>

          {organizations.length === 0 ? (
            <div className="px-2 py-4 text-center text-sm text-muted-foreground">
              {isLoading ? 'Loading...' : 'No organizations available'}
            </div>
          ) : (
            <div className="max-h-[calc(100vh-160px)] space-y-1 overflow-y-auto">
              {organizations.map((org) => (
                <OrgMenuItem
                  key={org.id}
                  org={org}
                  isSelected={org.id === currentOrgId && orgScope === 'current'}
                  onSelect={async () => {
                    // Picking a specific org from the dropdown implies the
                    // user wants to narrow to that org, so auto-flip the
                    // scope back to 'current' (if it was 'all'). This is a
                    // recovery affordance — switching from All to a single
                    // org would otherwise be a two-click operation.
                    if (orgScope === 'all') {
                      useOrgStore.getState().setOrgScope('current');
                    }
                    if (org.id !== currentOrgId || orgScope === 'all') {
                      setOrganization(org.id);
                      // Wait for any in-flight /auth/refresh to settle before
                      // navigating — leaving while a refresh is mid-flight
                      // clears the cookie jti and bounces to /login (#950,
                      // fixed in #953/#956/#958).
                      await waitForPendingRefresh();
                      const redirect = getOrgSwitchRedirect(window.location.pathname);
                      if (redirect) {
                        window.location.href = redirect;
                      } else {
                        window.location.reload();
                      }
                    }
                  }}
                  sites={sites}
                  currentSiteId={currentSiteId}
                  onSelectSite={async (siteId) => {
                    const changed = siteId !== currentSiteId;
                    setSite(siteId);
                    setIsOpen(false);
                    if (changed) {
                      // Same #950 refresh-race guard before reloading.
                      await waitForPendingRefresh();
                      window.location.reload();
                    }
                  }}
                />
              ))}
            </div>
          )}
        </div>
      )}
      </div>
    </div>
  );
}
