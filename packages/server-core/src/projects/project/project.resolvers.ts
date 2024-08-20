/*
CPAL-1.0 License

The contents of this file are subject to the Common Public Attribution License
Version 1.0. (the "License"); you may not use this file except in compliance
with the License. You may obtain a copy of the License at
https://github.com/ir-engine/ir-engine/blob/dev/LICENSE.
The License is based on the Mozilla Public License Version 1.1, but Sections 14
and 15 have been added to cover use of software over a computer network and 
provide for limited attribution for the Original Developer. In addition, 
Exhibit A has been modified to be consistent with Exhibit B.

Software distributed under the License is distributed on an "AS IS" basis,
WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for the
specific language governing rights and limitations under the License.

The Original Code is Infinite Reality Engine.

The Original Developer is the Initial Developer. The Initial Developer of the
Original Code is the Infinite Reality Engine team.

All portions of the code written by the Infinite Reality Engine team are Copyright © 2021-2023 
Infinite Reality Engine. All Rights Reserved.
*/

// For more information about this file see https://dove.feathersjs.com/guides/cli/service.schemas.html
import { resolve, virtual } from '@feathersjs/schema'
import { v4 as uuidv4 } from 'uuid'

import {
  projectPermissionPath,
  ProjectPermissionType
} from '@ir-engine/common/src/schemas/projects/project-permission.schema'
import { ProjectQuery, ProjectType } from '@ir-engine/common/src/schemas/projects/project.schema'
import { projectSettingPath } from '@ir-engine/common/src/schemas/setting/project-setting.schema'
import { fromDateTimeSql, getDateTimeSql } from '@ir-engine/common/src/utils/datetime-sql'
import type { HookContext } from '@ir-engine/server-core/declarations'

export const projectResolver = resolve<ProjectType, HookContext>({
  projectPermissions: virtual(async (project, context) => {
    console.log('Resolving project-permissions', project)
    const perms = context.params.populateProjectPermissions
      ? ((await context.app.service(projectPermissionPath).find({
          query: {
            projectId: project.id
          },
          paginate: false
        })) as ProjectPermissionType[])
      : []
    console.log('project-permissions', perms)
    return perms
  }),

  settings: virtual(async (project, context) => {
    console.log('Resolving project settings', project)
    if (context.event !== 'removed') {
      const settings = await context.app.service(projectSettingPath).find({
        query: {
          projectId: project.id
        },
        paginate: false
      })
      console.log('returning settings', project)
      return settings
    }
  }),

  assetsOnly: virtual(async (project, context) => {
    console.log('Resolving assetsOnly', project)
    const assetsOnly = !!project.assetsOnly
    console.log('assetsOnly', assetsOnly)
    return assetsOnly
  }),

  hasLocalChanges: virtual(async (project, context) => {
    console.log('Resolving hasLocalChanges', project)
    const hasLocalChanges = !!project.hasLocalChanges
    console.log('returning hasLocalChanges', hasLocalChanges)
    return hasLocalChanges
  }),

  needsRebuild: virtual(async (project, context) => {
    console.log('Resolving needsRebuild', project)
    const needsRebuild = !!project.needsRebuild
    console.log('returning needsRebuild', needsRebuild)
  }),

  commitDate: virtual(async (project) => {
    console.log('resolving commitDate', project)
    if (project.commitDate) {
      const commitDate = fromDateTimeSql(project.commitDate)
      console.log('returning commitDate', commitDate)
      return commitDate
    }
  }),
  createdAt: virtual(async (project) => fromDateTimeSql(project.createdAt)),
  updatedAt: virtual(async (project) => fromDateTimeSql(project.updatedAt))
})

export const projectExternalResolver = resolve<ProjectType, HookContext>({})

export const projectDataResolver = resolve<ProjectType, HookContext>({
  id: async () => {
    console.log('Creating project ID')
    return uuidv4()
  },
  createdAt: getDateTimeSql,
  updatedBy: async (_, __, context) => {
    console.log('Adding updatedBy', context?.params?.user?.id)
    const returned = context?.params?.user?.id || null
    console.log('userId to add', returned)
    return returned
  },
  updatedAt: getDateTimeSql
})

export const projectPatchResolver = resolve<ProjectType, HookContext>({
  updatedBy: async (_, __, context) => {
    console.log('Adding updatedBy')
    const returned = context.params?.user?.id || null
    console.log('userId to add', returned)
    return returned
  },
  updatedAt: getDateTimeSql
})

export const projectQueryResolver = resolve<ProjectQuery, HookContext>({})
