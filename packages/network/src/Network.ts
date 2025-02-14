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

import { Action, HyperFlux, NetworkID, PeerID, Topic, UserID, getState } from '@ir-engine/hyperflux'
import { DataChannelRegistryState, DataChannelType } from './DataChannelRegistry'
import { MediaTagType, NetworkPeer } from './NetworkState'
import { NetworkActionFunctions } from './functions/NetworkActionFunctions'

/**
 * Network topics are classes of networks. Topics are used to disitinguish between multiple networks of the same type.
 */
export const NetworkTopics = {
  world: 'world' as Topic,
  media: 'media' as Topic
}

export interface JitterBufferEntry {
  simulationTime: number
  read: () => void
}

export type Network<Ext = unknown> = {
  /** Connected peers */
  peers: Record<PeerID, NetworkPeer>

  /** Map of numerical peer index to peer IDs */
  peerIndexToPeerID: Record<number, PeerID>

  /** Map of peer IDs to numerical peer index */
  peerIDToPeerIndex: Record<PeerID, number>

  /**
   * The index to increment when a new peer connects
   * NOTE: Must only be updated by the host
   * @todo - make this a function and throw an error if we are not the host
   */
  peerIndexCount: number

  /** Connected users */
  users: Record<UserID, PeerID[]>

  /** Map of numerical user index to user client IDs */
  userIndexToUserID: Record<number, UserID>

  /** Map of user client IDs to numerical user index */
  userIDToUserIndex: Record<UserID, number>

  /**
   * The index to increment when a new user joins
   * NOTE: Must only be updated by the host
   * @todo - make this a function and throw an error if we are not the host
   */
  userIndexCount: number

  /**
   * The UserID of the host
   * - will either be a user's UserID, or an instance server's InstanceId
   * @todo rename to hostUserID to differentiate better from hostPeerID
   * @todo change from UserID to PeerID and change "get hostPeerID()" to "get hostUserID()"
   */
  hostPeerID: PeerID

  readonly hostUserID: UserID

  /**
   * The ID of this network, equivalent to the InstanceID of an instance
   */
  id: NetworkID

  /**
   * The network is ready for sending messages and data
   */
  ready: boolean

  /**
   * The transport used by this network.
   */
  messageToPeer: (peerId: PeerID, data: any) => void
  messageToAll: (data: any) => void
  onMessage: (fromPeerID: PeerID, data: any) => void
  bufferToPeer: (dataChannelType: DataChannelType, fromPeerID: PeerID, peerId: PeerID, data: any) => void
  bufferToAll: (dataChannelType: DataChannelType, fromPeerID: PeerID, data: any) => void
  onBuffer: (dataChannelType: DataChannelType, fromPeerID: PeerID, data: any) => void

  /** @todo maybe we should change the verbiage to 'muted'? does this make sense for video? */
  pauseTrack: (peerID: PeerID, track: MediaTagType, pause: boolean) => void
  /** @todo add more abstractions here */

  readonly isHosting: boolean

  topic: Topic
} & Ext

/** Interface for the Transport. */
export const createNetwork = <Ext = unknown>(
  id: NetworkID,
  hostPeerID: PeerID,
  topic: Topic,
  extension?: Ext
): Network<Ext> => {
  const network = {
    messageToPeer: (peerId: PeerID, data: any) => {
      network.peers[peerId]?.transport?.message?.(data)
    },
    messageToAll: (data: any) => {
      for (const peer of Object.values(network.peers)) network.messageToPeer(peer.peerID, data)
    },
    onMessage: (fromPeerID: PeerID, message: any) => {
      const actions = message as any as Required<Action>[]
      // const actions = decode(new Uint8Array(message)) as IncomingActionType[]
      NetworkActionFunctions.receiveIncomingActions(network, fromPeerID, actions)
    },
    bufferToPeer: (dataChannelType: DataChannelType, fromPeerID: PeerID, peerID: PeerID, data: any) => {
      network.peers[peerID]?.transport?.buffer?.(dataChannelType, data)
    },
    bufferToAll: (dataChannelType: DataChannelType, fromPeerID: PeerID, data: any) => {
      for (const peer of Object.values(network.peers))
        network.bufferToPeer(dataChannelType, fromPeerID, peer.peerID, data)
    },
    onBuffer: (dataChannelType: DataChannelType, fromPeerID: PeerID, data: any) => {
      const dataChannelFunctions = getState(DataChannelRegistryState)[dataChannelType]
      if (dataChannelFunctions) {
        for (const func of dataChannelFunctions) func(network, dataChannelType, fromPeerID, data)
      }
    },
    pauseTrack(peerID, track, pause) {
      // noop
    },
    ...extension,
    peers: {},
    peerIndexToPeerID: {},
    peerIDToPeerIndex: {},
    peerIndexCount: 0,
    users: {},
    userIndexToUserID: {},
    userIDToUserIndex: {},
    userIndexCount: 0,
    hostPeerID,
    get hostUserID() {
      return network.peers[network.hostPeerID]?.userId
    },
    id,
    ready: false,
    get isHosting() {
      return HyperFlux.store.peerID === network.hostPeerID
    },
    topic
  } as Network<Ext>

  return network
}
