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

import {AuthenticationRequest, AuthenticationResult} from '@feathersjs/authentication'
import {Paginated, Params} from '@feathersjs/feathers'
import {random} from 'lodash'

import {avatarPath, AvatarType} from '@ir-engine/common/src/schemas/user/avatar.schema'
import {identityProviderPath} from '@ir-engine/common/src/schemas/user/identity-provider.schema'
import {userApiKeyPath, UserApiKeyType} from '@ir-engine/common/src/schemas/user/user-api-key.schema'
import {InviteCode, UserName, userPath} from '@ir-engine/common/src/schemas/user/user.schema'

import {Application} from '../../../declarations'
import config from '../../appconfig'
import {RedirectConfig} from '../../types/OauthStrategies'
import getFreeInviteCode from '../../util/get-free-invite-code'
import makeInitialAdmin from '../../util/make-initial-admin'
import CustomOAuthStrategy, {CustomOAuthParams} from './custom-oauth'
import loginToken from "../login-token/login-token";
import {loginTokenPath} from "@ir-engine/common/src/schemas/user/login-token.schema";
import { v4 } from 'uuid'
import {toDateTimeSql} from "@ir-engine/common/src/utils/datetime-sql";
import moment from "moment/moment";

export class Googlestrategy extends CustomOAuthStrategy {
  constructor(app: Application) {
    super()
    this.app = app
  }

  async getEntityData(profile: any, entity: any, params: Params): Promise<any> {
    const baseData = await super.getEntityData(profile, null, {})

    const authResult = entity
      ? entity
      : await (this.app.service('authentication') as any).strategies.jwt.authenticate(
          { accessToken: params?.authentication?.accessToken },
          {}
        )
    const identityProvider = authResult[identityProviderPath] ? authResult[identityProviderPath] : authResult
    const userId = identityProvider ? identityProvider.userId : params?.query ? params.query.userId : undefined
    return {
      ...baseData,
      accountIdentifier: profile.email,
      type: 'google',
      email: profile.email,
      userId
    }
  }

  async updateEntity(entity: any, profile: any, params: Params): Promise<any> {
    console.log('google updateEntity', entity, profile, params)
    const authResult = await (this.app.service('authentication') as any).strategies.jwt.authenticate(
      { accessToken: params?.authentication?.accessToken },
      {}
    )
    const profileEmail = profile.email
    if (!entity.userId) {
      const avatars = (await this.app
        .service(avatarPath)
        .find({ isInternal: true, query: { isPublic: true, $limit: 1000 } })) as Paginated<AvatarType>
      const code = (await getFreeInviteCode(this.app)) as InviteCode
      const newUser = await this.app.service(userPath).create({
        name: '' as UserName,
        isGuest: false,
        inviteCode: code,
        avatarId: avatars.data[random(avatars.data.length - 1)].id,
        scopes: []
      })
      entity.userId = newUser.id
      await this.app.service(identityProviderPath).patch(entity.id, {
        userId: newUser.id,
        email: entity.email
      })
    } else
      await this.app.service(identityProviderPath)._patch(entity.id, {
        email: entity.email
      })
    const identityProvider = authResult[identityProviderPath]
    const user = await this.app.service(userPath).get(entity.userId)
    await makeInitialAdmin(this.app, user.id)
    if (user.isGuest)
      await this.app.service(userPath).patch(entity.userId, {
        isGuest: false
      })
    const apiKey = (await this.app.service(userApiKeyPath).find({
      query: {
        userId: entity.userId
      }
    })) as Paginated<UserApiKeyType>
    if (apiKey.total === 0)
      await this.app.service(userApiKeyPath).create({
        userId: entity.userId
      })
    if (entity.type !== 'guest' && identityProvider.type === 'guest') {
      await this.app.service(identityProviderPath).remove(identityProvider.id)
      await this.app.service(userPath).remove(identityProvider.userId)
      await this.userLoginEntry(entity, params)
      return super.updateEntity(entity, profile, params)
    }
    const existingEntity = await super.findEntity(profile, params)
    if (!existingEntity) {
      profile.userId = user.id
      const newIP = await super.createEntity(profile, params)

      if (entity.type === 'guest') {
        const existingIdentityProviders = await this.app.service(identityProviderPath).find({
          query: {
            $or: [
              {
                email: profileEmail
              },
              {
                token: profileEmail
              }
            ],
            id: {
              $ne: entity.id
            }
          }
        })
        console.log('existingIdentityProviders', existingIdentityProviders)
        if (existingIdentityProviders.total > 0) {
          const loginToken = await app.service(loginTokenPath).create({
            identityProviderId: newIP.id,
            expiresAt: toDateTimeSql(moment().utc().add(10, 'minutes').toDate())
          })
          const returned = {
            ...entity,
            associateEmail: profileEmail,
            loginToken: loginToken.token,
            promptForConnection: true
          }
          console.log('returned', returned)
          return returned
        } else {
          await this.app.service(identityProviderPath).remove(entity.id)
          await this.userLoginEntry(newIP, params)
          return newIP
        }
      }
    } else if (existingEntity.userId === identityProvider.userId) {
      await this.userLoginEntry(existingEntity, params)
      return existingEntity
    } else {
      throw new Error('Another user is linked to this account')
    }
  }

  async getRedirect(data: AuthenticationResult | Error, params: CustomOAuthParams): Promise<string> {
    console.log('google getRedirect', data, params)
    let redirectConfig: RedirectConfig
    try {
      redirectConfig = JSON.parse(params.redirect!)
    } catch {
      redirectConfig = {}
    }
    let { domain: redirectDomain, path: redirectPath, instanceId: redirectInstanceId } = redirectConfig
    redirectDomain = redirectDomain ? `${redirectDomain}/auth/oauth/google` : config.authentication.callback.google

    if (data instanceof Error || Object.getPrototypeOf(data) === Error.prototype) {
      const err = data.message as string
      return redirectDomain + `?error=${err}`
    }

    console.log('IP TO CHECK', data[identityProviderPath])
    if (data[identityProviderPath]?.promptForConnection) {
      let redirectUrl = `${redirectDomain}?promptForConnection=true&associateEmail=${data[identityProviderPath].associateEmail}`
      if (redirectPath) {
        redirectUrl = redirectUrl.concat(`&path=${redirectPath}`)
      }
      if (redirectInstanceId) {
        redirectUrl = redirectUrl.concat(`&instanceId=${redirectInstanceId}`)
      }

      return redirectUrl
    } else {
      const loginType = params.query?.userId ? 'connection' : 'login'
      let redirectUrl = `${redirectDomain}?token=${data.accessToken}&type=${loginType}`
      if (redirectPath) {
        redirectUrl = redirectUrl.concat(`&path=${redirectPath}`)
      }
      if (redirectInstanceId) {
        redirectUrl = redirectUrl.concat(`&instanceId=${redirectInstanceId}`)
      }

      return redirectUrl
    }
  }

  async authenticate(authentication: AuthenticationRequest, originalParams: Params) {
    console.log('google authenticate', authentication, originalParams)
    if (authentication.error)
      throw new Error(
        'There was a problem with the Google OAuth login flow: ' + authentication.error_description ||
          authentication.error
      )
    const entity: string = this.configuration.entity
    const { provider, ...params } = originalParams
    const profile = await super.getProfile(authentication, params)
    const existingEntity = (await super.findEntity(profile, params)) || (await super.getCurrentEntity(params))

    const authEntity = !existingEntity
        ? await this.createEntity(profile, params)
        : await this.updateEntity(existingEntity, profile, params)

    console.log('Google authEntity', entity, authEntity)
    const fetchedEntity = await super.getEntity(authEntity, originalParams)
    console.log('fetched entity', fetchedEntity)
    if (authEntity.promptForConnection) {
      fetchedEntity.promptForConnection = authEntity.promptForConnection
      fetchedEntity.associateEmail = authEntity.associateEmail
    }

    console.log('returned entity', fetchedEntity)

    return {
      authentication: { strategy: this.name },
      [entity]: fetchedEntity
    }
  }
}
export default Googlestrategy
