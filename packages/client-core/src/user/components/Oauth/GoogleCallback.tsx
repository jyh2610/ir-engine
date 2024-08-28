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

import React, { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useLocation } from 'react-router-dom'

import { config } from '@ir-engine/common/src/config'
import { InstanceID } from '@ir-engine/common/src/schema.type.module'
import { getMutableState, useHookstate } from '@ir-engine/hyperflux'
import Button from '@ir-engine/ui/src/primitives/mui/Button'
import Container from '@ir-engine/ui/src/primitives/mui/Container'

import { AuthService, AuthState } from '../../services/AuthService'
import styles from './styles.module.scss'

const GoogleCallbackComponent = (props): JSX.Element => {
  const { t } = useTranslation()
  const initialState = { error: '', token: '', email: '', promptForConnection: 'false', loginToken }
  const [state, setState] = useState(initialState)
  const search = new URLSearchParams(useLocation().search)

  useEffect(() => {
    const error = search.get('error') as string
    const token = search.get('token') as string
    const type = search.get('type') as string
    const path = search.get('path') as string
    const promptForConnection = search.get('promptForConnection') as string
    const loginToken = search.get('loginToken') as string
    const email = search.get('associateEmail') as string
    const instanceId = search.get('instanceId') as InstanceID

    if (!error) {
      if (promptForConnection === 'true') {

      }
      else if (type === 'connection') {
        const user = useHookstate(getMutableState(AuthState)).user
        AuthService.refreshConnections(user.id.value!)
      } else {
        let redirectSuccess = `${path}`
        if (instanceId != null) redirectSuccess += `?instanceId=${instanceId}`
        AuthService.loginUserByJwt(token, redirectSuccess || '/', '/')
      }
    }

    setState({ ...state, error, token, promptForConnection, email, loginToken })
  }, [])

  function redirectToRoot() {
    window.location.href = '/'
  }

  function doRedirect(connect=false) {
    const path = search.get('path') as string
    const email = search.get('associateEmail') as string
    const loginToken = search.get('loginToken') as string
    const instanceId = search.get('instanceId') as InstanceID
    let redirect = config.client.clientUrl
    if (path != null) redirect += path
    if (instanceId != null) redirect += `?instanceId=${instanceId}`
    let callback = `${config.client.serverUrl}/login/${loginToken}`
    if (connect) callback += `&associateEmail=${email}&redirectUrl=${redirect}`
    console.log('google accept callback', callback)
    window.location.href = callback
  }

  return state.error && state.error !== '' ? (
    <Container className={styles.oauthError}>
      <div className={styles.title}>{t('user:oauth.authFailed', { service: 'Google' })}</div>
      <div className={styles.message}>{state.error}</div>
      <Button onClick={redirectToRoot} className={styles.gradientButton}>
        {t('user:oauth.redirectToRoot')}
      </Button>
    </Container>
  ) : state.promptForConnection === 'true' ? (
      <Container className={styles.promptForConnection}>
        <div className={styles.title}>{t('user:oauth.promptForConnection')}</div>
        <div className={styles.message}>{t('user:oauth.askConnection', { service: 'Google', email: state.email })}</div>
        <div className="flex">
          <Button onClick={() => doRedirect(true)} className={styles.acceptBtn}>
            {t('user:oauth.acceptConnection')}
          </Button>
          <Button onClick={() => doRedirect(false)} className={styles.declineBtn}>
            {t('user:oauth.declineConnection')}
          </Button>
        </div>
      </Container>
  ) : (
    <Container>{t('user:oauth.authenticating')}</Container>
  )
}

export const GoogleCallback = GoogleCallbackComponent as any
