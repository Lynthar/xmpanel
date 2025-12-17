import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { usersApi } from '@/lib/api'
import { useAuthStore } from '@/store/auth'
import { useForm } from 'react-hook-form'
import toast from 'react-hot-toast'
import {
  Users as UsersIcon,
  Plus,
  Pencil,
  Trash2,
  X,
  Shield,
  ShieldCheck,
} from 'lucide-react'
import clsx from 'clsx'

interface User {
  id: number
  username: string
  email: string
  role: string
  mfa_enabled: boolean
  last_login_at?: string
  created_at: string
}

interface CreateUserForm {
  username: string
  email: string
  password: string
  role: string
}

interface EditUserForm {
  email?: string
  password?: string
  role?: string
}

export default function Users() {
  const queryClient = useQueryClient()
  const { user: currentUser } = useAuthStore()
  const [showAddModal, setShowAddModal] = useState(false)
  const [editingUser, setEditingUser] = useState<User | null>(null)

  const { data: users, isLoading } = useQuery({
    queryKey: ['users'],
    queryFn: async () => {
      const response = await usersApi.list()
      return response.data as User[]
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: number) => usersApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      toast.success('User deleted')
    },
    onError: (error: unknown) => {
      const err = error as { response?: { data?: { error?: string } } }
      toast.error(err.response?.data?.error || 'Failed to delete user')
    },
  })

  const handleDelete = (user: User) => {
    if (user.id === currentUser?.id) {
      toast.error('Cannot delete your own account')
      return
    }
    if (confirm(`Delete user ${user.username}?`)) {
      deleteMutation.mutate(user.id)
    }
  }

  const roleColors: Record<string, string> = {
    superadmin: 'badge-red',
    admin: 'badge-blue',
    operator: 'badge-yellow',
    viewer: 'badge-gray',
    auditor: 'badge-green',
  }

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">System Users</h1>
          <p className="text-gray-400 mt-1">Manage users who can access XMPanel</p>
        </div>
        <button onClick={() => setShowAddModal(true)} className="btn btn-primary flex items-center gap-2">
          <Plus className="w-4 h-4" />
          Add User
        </button>
      </div>

      {/* Users table */}
      <div className="card">
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500" />
          </div>
        ) : users?.length === 0 ? (
          <div className="text-center py-12">
            <UsersIcon className="w-12 h-12 text-gray-600 mx-auto mb-4" />
            <p className="text-gray-400">No users found</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-700">
                  <th className="table-header">User</th>
                  <th className="table-header">Role</th>
                  <th className="table-header">MFA</th>
                  <th className="table-header">Last Login</th>
                  <th className="table-header">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700">
                {users?.map((user) => (
                  <tr key={user.id} className="hover:bg-gray-700/50">
                    <td className="table-cell">
                      <div>
                        <p className="font-medium text-white">{user.username}</p>
                        <p className="text-sm text-gray-400">{user.email}</p>
                      </div>
                    </td>
                    <td className="table-cell">
                      <span className={clsx('badge capitalize', roleColors[user.role] || 'badge-gray')}>
                        {user.role}
                      </span>
                    </td>
                    <td className="table-cell">
                      {user.mfa_enabled ? (
                        <span title="MFA Enabled"><ShieldCheck className="w-5 h-5 text-green-400" /></span>
                      ) : (
                        <span title="MFA Disabled"><Shield className="w-5 h-5 text-gray-500" /></span>
                      )}
                    </td>
                    <td className="table-cell text-gray-400">
                      {user.last_login_at
                        ? new Date(user.last_login_at).toLocaleString()
                        : 'Never'}
                    </td>
                    <td className="table-cell">
                      <div className="flex gap-2">
                        <button
                          onClick={() => setEditingUser(user)}
                          className="p-1 text-gray-400 hover:text-white"
                          title="Edit"
                        >
                          <Pencil className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleDelete(user)}
                          className="p-1 text-gray-400 hover:text-red-400"
                          title="Delete"
                          disabled={user.id === currentUser?.id}
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Add user modal */}
      {showAddModal && (
        <AddUserModal
          onClose={() => setShowAddModal(false)}
          onSuccess={() => {
            setShowAddModal(false)
            queryClient.invalidateQueries({ queryKey: ['users'] })
          }}
        />
      )}

      {/* Edit user modal */}
      {editingUser && (
        <EditUserModal
          user={editingUser}
          onClose={() => setEditingUser(null)}
          onSuccess={() => {
            setEditingUser(null)
            queryClient.invalidateQueries({ queryKey: ['users'] })
          }}
        />
      )}
    </div>
  )
}

function AddUserModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {
  const [loading, setLoading] = useState(false)
  const { register, handleSubmit, formState: { errors } } = useForm<CreateUserForm>({
    defaultValues: { role: 'viewer' },
  })

  const onSubmit = async (data: CreateUserForm) => {
    setLoading(true)
    try {
      await usersApi.create(data)
      toast.success('User created')
      onSuccess()
    } catch (error: unknown) {
      const err = error as { response?: { data?: { error?: string } } }
      toast.error(err.response?.data?.error || 'Failed to create user')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50">
      <div className="w-full max-w-md bg-gray-800 rounded-xl border border-gray-700">
        <div className="flex items-center justify-between p-4 border-b border-gray-700">
          <h2 className="text-lg font-semibold text-white">Add User</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit(onSubmit)} className="p-4 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Username</label>
            <input
              type="text"
              className="input"
              {...register('username', { required: 'Required', minLength: { value: 3, message: 'Min 3 characters' } })}
            />
            {errors.username && <p className="mt-1 text-sm text-red-400">{errors.username.message}</p>}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Email</label>
            <input
              type="email"
              className="input"
              {...register('email', { required: 'Required' })}
            />
            {errors.email && <p className="mt-1 text-sm text-red-400">{errors.email.message}</p>}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Password</label>
            <input
              type="password"
              className="input"
              {...register('password', { required: 'Required', minLength: { value: 12, message: 'Min 12 characters' } })}
            />
            {errors.password && <p className="mt-1 text-sm text-red-400">{errors.password.message}</p>}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Role</label>
            <select className="input" {...register('role')}>
              <option value="viewer">Viewer</option>
              <option value="operator">Operator</option>
              <option value="admin">Admin</option>
              <option value="auditor">Auditor</option>
            </select>
          </div>

          <div className="flex justify-end gap-3 pt-4">
            <button type="button" onClick={onClose} className="btn btn-secondary">Cancel</button>
            <button type="submit" disabled={loading} className="btn btn-primary">
              {loading ? 'Creating...' : 'Create User'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function EditUserModal({ user, onClose, onSuccess }: { user: User; onClose: () => void; onSuccess: () => void }) {
  const [loading, setLoading] = useState(false)
  const { register, handleSubmit } = useForm<EditUserForm>({
    defaultValues: { email: user.email, role: user.role },
  })

  const onSubmit = async (data: EditUserForm) => {
    setLoading(true)
    try {
      const updateData: EditUserForm = {}
      if (data.email && data.email !== user.email) updateData.email = data.email
      if (data.password) updateData.password = data.password
      if (data.role && data.role !== user.role) updateData.role = data.role

      if (Object.keys(updateData).length === 0) {
        toast('No changes to save')
        onClose()
        return
      }

      await usersApi.update(user.id, updateData)
      toast.success('User updated')
      onSuccess()
    } catch (error: unknown) {
      const err = error as { response?: { data?: { error?: string } } }
      toast.error(err.response?.data?.error || 'Failed to update user')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50">
      <div className="w-full max-w-md bg-gray-800 rounded-xl border border-gray-700">
        <div className="flex items-center justify-between p-4 border-b border-gray-700">
          <h2 className="text-lg font-semibold text-white">Edit User: {user.username}</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit(onSubmit)} className="p-4 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Email</label>
            <input type="email" className="input" {...register('email')} />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              New Password <span className="text-gray-500">(leave blank to keep current)</span>
            </label>
            <input type="password" className="input" {...register('password')} />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Role</label>
            <select className="input" {...register('role')}>
              <option value="viewer">Viewer</option>
              <option value="operator">Operator</option>
              <option value="admin">Admin</option>
              <option value="auditor">Auditor</option>
            </select>
          </div>

          <div className="flex justify-end gap-3 pt-4">
            <button type="button" onClick={onClose} className="btn btn-secondary">Cancel</button>
            <button type="submit" disabled={loading} className="btn btn-primary">
              {loading ? 'Saving...' : 'Save Changes'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
