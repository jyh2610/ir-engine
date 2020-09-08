import { Quaternion, Box, Cylinder, Vec3, RaycastVehicle, Body } from 'cannon-es';
import { Entity } from '../../ecs/classes/Entity';
import { Behavior } from '../../common/interfaces/Behavior';
import { getMutableComponent, getComponent } from '../../ecs/functions/EntityFunctions';
import { Object3DComponent } from '../../common/components/Object3DComponent';
import { TransformComponent } from '../../transform/components/TransformComponent';
import { AssetLoader } from "@xr3ngine/engine/src/assets/components/AssetLoader";
import { PhysicsManager } from '../components/PhysicsManager';
import { VehicleBody } from '../../physics/components/VehicleBody';
import { Engine } from "@xr3ngine/engine/src/ecs/classes/Engine";

import { createConvexGeometry } from './PhysicsBehaviors';

const quaternion = new Quaternion();

export const VehicleBehavior: Behavior = (entity: Entity, args): void => {
  if (args.phase == 'onAdded') {
    const vehicleComponent = getMutableComponent(entity, VehicleBody) as VehicleBody;
    const assetLoader = getMutableComponent<AssetLoader>(entity, AssetLoader as any);
    assetLoader.onLoaded = asset => {
      asset.scene.traverse(mesh => {
        if (mesh.name == 'door_3') {

          vehicleComponent.vehicleMesh = mesh
          //Engine.scene.remove( Engine.scene.getObjectByProperty( 'uuid', mesh.uuid ) );
        } else {
        //  mesh.visible = false;
        }
//      vehicleMesh = asset.scene.getObjectByName()
        console.log(mesh)
      })
    }



    const [vehicle, wheelBodies] = createVehicleBody(entity);
    vehicleComponent.vehiclePhysics = vehicle;
    vehicle.addToWorld(PhysicsManager.instance.physicsWorld);

    for (let i = 0; i < wheelBodies.length; i++) {
      PhysicsManager.instance.physicsWorld.addBody(wheelBodies[i]);
    }

  } else if (args.phase == 'onUpdate') {

    const transform = getMutableComponent<TransformComponent>(entity, TransformComponent);
    const vehicleComponent = getMutableComponent(entity, VehicleBody) as VehicleBody;

    if( vehicleComponent.vehiclePhysics != null && vehicleComponent.vehicleMesh != null){

      const vehicle = vehicleComponent.vehiclePhysics.chassisBody;
      //console.log(vehicleComponent);


      transform.position.set(
        vehicle.position.x,
        vehicle.position.y,
        vehicle.position.z
      )
/*
      transform.rotation.set(
        vehicle.quaternion.x,
        vehicle.quaternion.y,
        vehicle.quaternion.z,
        vehicle.quaternion.w
      )
*/

  } else {
    console.warn("User data for vehicle not found")
  }


  } else if (args.phase == 'onRemoved') {
    const object = getComponent<Object3DComponent>(entity, Object3DComponent, true)?.value;
    if (!object) {
      return
    }
    const body = object.userData.vehicle;
    delete object.userData.vehicle;
    PhysicsManager.instance.physicsWorld.removeBody(body);
  }
};

export function createVehicleBody (entity: Entity ): [RaycastVehicle, Body[]] {
  const transform = getComponent<TransformComponent>(entity, TransformComponent);
  let chassisBody;

  const chassisShape = new Box(new Vec3(1, 1.2, 3));
  chassisBody = new Body({ mass: 150 });
  chassisBody.addShape(chassisShape);

  //  let
  chassisBody.position.x = transform.position.x
  chassisBody.position.y = transform.position.y
  chassisBody.position.z = transform.position.z
  //  chassisBody.angularVelocity.set(0, 0, 0.5);
  const options = {
    radius: 0.5,
    directionLocal: new Vec3(0, -1, 0),
    suspensionStiffness: 30,
    suspensionRestLength: 0.3,
    frictionSlip: 5,
    dampingRelaxation: 2.3,
    dampingCompression: 4.4,
    maxSuspensionForce: 100000,
    rollInfluence: 0.01,
    axleLocal: new Vec3(-1, 0, 0),
    chassisConnectionPointLocal: new Vec3(),
    maxSuspensionTravel: 0.3,
    customSlidingRotationalSpeed: -30,
    useCustomSlidingRotationalSpeed: true
  };

  // Create the vehicle
  const vehicle = new RaycastVehicle({
    chassisBody: chassisBody,
    indexUpAxis: 1,
    indexRightAxis: 0,
    indexForwardAxis: 2
  });

  options.chassisConnectionPointLocal.set(1.4, -0.6, 2.35);
  vehicle.addWheel(options);

  options.chassisConnectionPointLocal.set(-1.4, -0.6, 2.35);
  vehicle.addWheel(options);

  options.chassisConnectionPointLocal.set(-1.4, -0.6, -2.2);
  vehicle.addWheel(options);

  options.chassisConnectionPointLocal.set(1.4, -0.6, -2.2);
  vehicle.addWheel(options);

  const wheelBodies = [];
  for (let i = 0; i < vehicle.wheelInfos.length; i++) {
    const cylinderShape = new Cylinder(1, 1, 0.1, 20);
    const wheelBody = new Body({
      mass: 0
    });
    wheelBody.type = Body.KINEMATIC;
    wheelBody.collisionFilterGroup = 0; // turn off collisions
    wheelBody.addShape(cylinderShape);
    wheelBodies.push(wheelBody);
    // demo.addVisual(wheelBody);
    // addBody(wheelBody);
  }

  return [vehicle, wheelBodies];
}
