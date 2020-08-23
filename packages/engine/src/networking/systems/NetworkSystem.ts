import { Entity } from '../../ecs/classes/Entity';
import { System } from '../../ecs/classes/System';
import { addComponent, createEntity } from '../../ecs/functions/EntityFunctions';
import { Network } from '../components/Network';
import { NetworkClient } from '../components/NetworkClient';
import { NetworkObject } from '../components/NetworkObject';

export class NetworkSystem extends System {
  public static instance: NetworkSystem = null

  connectToServer(ip: string, port: number){
    Network.instance.transport.initialize(ip, port);
    Network.instance.isInitialized = true;
  }

  init (attributes) {
    NetworkSystem.instance = this
console.log("NetworkSystem schema: ")

    const { schema } = attributes
    // Create a Network entity (singleton)
    const networkEntity = createEntity();
    addComponent(networkEntity, Network);

    // Late initialization of network
    Network.instance.schema = schema
    Network.instance.transport = new (schema.transport)();
    console.log("NetowrkSystem ready, run connectToServer to... connect to the server!")
  }
  
  public execute (): void {
    this.queryResults.network.all?.forEach((entity: Entity) => {
      // console.log(entity)
    })
  }

  static queries: any = {
    network: {
      components: [Network]
    },
    networkObject: {
      components: [NetworkObject]
    },
    networkOwners: {
      components: [NetworkClient]
    }
  }

}
