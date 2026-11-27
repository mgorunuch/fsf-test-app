import { redirect } from "@tanstack/react-router"

import { type UserPublic, UsersService } from "@/client"

/**
 * Atomic permission names, mirroring the backend LOCKED ARCHITECTURE.
 * - super        : unrestricted; a holder passes every permission check.
 * - users:read   : list/view any user; view the roles list.
 * - users:manage : create/update/delete users and change role assignments.
 * - metrics:read : view the metrics page/endpoint.
 */
export const PERMISSIONS = {
  usersRead: "users:read",
  usersManage: "users:manage",
  metricsRead: "metrics:read",
} as const

export type Permission = (typeof PERMISSIONS)[keyof typeof PERMISSIONS]

const SUPER_PERMISSION = "super"

/**
 * Whether the given user holds `permission`. A user with the `super`
 * permission passes every check, mirroring the backend authorization layer.
 */
export function hasPermission(
  user: Pick<UserPublic, "permissions"> | null | undefined,
  permission: string,
): boolean {
  const permissions = user?.permissions ?? []
  return (
    permissions.includes(SUPER_PERMISSION) || permissions.includes(permission)
  )
}

/**
 * Route guard for `beforeLoad`: loads the current user and redirects to "/"
 * unless they hold `permission`. This protects against direct navigation to a
 * route the user is not allowed to see, instead of letting the page crash on a
 * 403 from its data loader.
 */
export async function requirePermission(permission: string): Promise<void> {
  const { data: user } = await UsersService.readUserMe()
  if (!hasPermission(user, permission)) {
    throw redirect({ to: "/" })
  }
}
