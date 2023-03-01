import mediasoup from 'mediasoup-client'

import { UserId } from '@xrengine/common/src/interfaces/UserId'
import { matches, Validator } from '@xrengine/engine/src/common/functions/MatchesUtils'
import { Engine } from '@xrengine/engine/src/ecs/classes/Engine'
import { getNearbyUsers } from '@xrengine/engine/src/networking/functions/getNearbyUsers'
import { defineAction, defineState, dispatchAction, getState, useState } from '@xrengine/hyperflux'

import { MediaStreamState } from '../../transports/MediaStreams'
import { ConsumerExtension, SocketWebRTCClientNetwork } from '../../transports/SocketWebRTCClientNetwork'
import { accessNetworkUserState } from '../../user/services/NetworkUserService'

//State
export const MediaState = defineState({
  name: 'MediaState',
  initial: () => ({
    isCamVideoEnabled: false,
    isCamAudioEnabled: false,
    isScreenVideoEnabled: false,
    isScreenAudioEnabled: false,
    isFaceTrackingEnabled: false,
    enableBydefault: true,
    nearbyLayerUsers: [] as UserId[],
    consumers: [] as ConsumerExtension[]
  })
})

export const MediaServiceReceptor = (action) => {
  const s = getState(MediaState)
  matches(action)
    .when(MediaStreamAction.setCamVideoStateAction.matches, (action) => {
      return s.isCamVideoEnabled.set(action.isEnable)
    })
    .when(MediaStreamAction.setCamAudioStateAction.matches, (action) => {
      return s.isCamAudioEnabled.set(action.isEnable)
    })
    .when(MediaStreamAction.setScreenVideoStateAction.matches, (action) => {
      return s.isScreenVideoEnabled.set(action.isEnable)
    })
    .when(MediaStreamAction.setScreenAudioStateAction.matches, (action) => {
      return s.isScreenAudioEnabled.set(action.isEnable)
    })
    .when(MediaStreamAction.setFaceTrackingStateAction.matches, (action) => {
      return s.isFaceTrackingEnabled.set(action.isEnable)
    })
    .when(MediaStreamAction.setMediaEnabledByDefaultAction.matches, (action) => {
      return s.enableBydefault.set(action.isEnable)
    })
    .when(MediaStreamAction.setConsumersAction.matches, (action) => {
      return s.consumers.set(action.consumers)
    })
}

export const accessMediaStreamState = () => getState(MediaState)
export const useMediaStreamState = () => useState(accessMediaStreamState())

let updateConsumerTimeout

//Service
export const MediaStreamService = {
  updateCamVideoState: () => {
    const mediaStreamState = getState(MediaStreamState)
    dispatchAction(
      MediaStreamAction.setCamVideoStateAction({
        isEnable: mediaStreamState.camVideoProducer.value != null && !mediaStreamState.videoPaused.value
      })
    )
  },
  updateCamAudioState: () => {
    const mediaStreamState = getState(MediaStreamState)
    dispatchAction(
      MediaStreamAction.setCamAudioStateAction({
        isEnable: mediaStreamState.camAudioProducer.value != null && !mediaStreamState.audioPaused.value
      })
    )
  },
  updateScreenVideoState: () => {
    const mediaStreamState = getState(MediaStreamState)
    dispatchAction(
      MediaStreamAction.setScreenVideoStateAction({
        isEnable: mediaStreamState.screenVideoProducer.value != null && !mediaStreamState.screenShareVideoPaused.value
      })
    )
  },
  updateScreenAudioState: () => {
    const mediaStreamState = getState(MediaStreamState)
    dispatchAction(
      MediaStreamAction.setScreenAudioStateAction({
        isEnable: mediaStreamState.screenAudioProducer.value != null && !mediaStreamState.screenShareAudioPaused.value
      })
    )
  },
  triggerUpdateConsumers: () => {
    if (!updateConsumerTimeout) {
      updateConsumerTimeout = setTimeout(() => {
        const mediaNetwork = Engine.instance.currentWorld.mediaNetwork as SocketWebRTCClientNetwork
        if (mediaNetwork) dispatchAction(MediaStreamAction.setConsumersAction({ consumers: mediaNetwork.consumers }))
        updateConsumerTimeout = null
      }, 1000)
    }
  },
  updateNearbyLayerUsers: () => {
    const mediaState = getState(MediaState)
    const UserState = accessNetworkUserState()

    const nonPartyUserIds = UserState.layerUsers
      .filter((user) => user.partyId.value == null)
      .map((user) => user.id.value)
    const nearbyUsers = getNearbyUsers(Engine.instance.userId, nonPartyUserIds)
    if (JSON.stringify(mediaState.nearbyLayerUsers.value) !== JSON.stringify(nearbyUsers))
      mediaState.nearbyLayerUsers.set(nearbyUsers)
  },
  updateFaceTrackingState: () => {
    const mediaStreamState = getState(MediaStreamState)
    dispatchAction(MediaStreamAction.setFaceTrackingStateAction({ isEnable: mediaStreamState.faceTracking.value }))
  },
  updateEnableMediaByDefault: () => {
    dispatchAction(MediaStreamAction.setMediaEnabledByDefaultAction({ isEnable: false }))
  }
}

//Action
export type BooleanAction = { [key: string]: boolean }
export class MediaStreamAction {
  static setCamVideoStateAction = defineAction({
    type: 'xre.client.MediaStream.CAM_VIDEO_CHANGED' as const,
    isEnable: matches.boolean
  })

  static setCamAudioStateAction = defineAction({
    type: 'xre.client.MediaStream.CAM_AUDIO_CHANGED' as const,
    isEnable: matches.boolean
  })

  static setScreenVideoStateAction = defineAction({
    type: 'xre.client.MediaStream.SCREEN_VIDEO_CHANGED' as const,
    isEnable: matches.boolean
  })

  static setScreenAudioStateAction = defineAction({
    type: 'xre.client.MediaStream.SCREEN_AUDIO_CHANGED' as const,
    isEnable: matches.boolean
  })

  static setFaceTrackingStateAction = defineAction({
    type: 'xre.client.MediaStream.FACE_TRACKING_CHANGED' as const,
    isEnable: matches.boolean
  })

  static setMediaEnabledByDefaultAction = defineAction({
    type: 'xre.client.MediaStream.MEDIA_ENABLE_BY_DEFAULT' as const,
    isEnable: matches.boolean
  })

  static setConsumersAction = defineAction({
    type: 'xre.client.MediaStream.CONSUMERS_CHANGED' as const,
    consumers: matches.any
  })
}
