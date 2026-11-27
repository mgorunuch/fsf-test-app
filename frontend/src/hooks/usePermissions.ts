import { hasPermission } from "@/lib/permissions"
import useAuth from "./useAuth"

/**
 * Exposes the current user's roles and resolved permissions, plus a
 * `hasPermission(p)` helper that treats "super" as passing any check
 * (mirroring the backend). Use it to gate UI the same way the API gates
 * access.
 */
const usePermissions = () => {
  const { user } = useAuth()

  return {
    roles: user?.roles ?? [],
    permissions: user?.permissions ?? [],
    hasPermission: (permission: string) => hasPermission(user, permission),
  }
}

export default usePermissions
