import { System, Entity } from "ecsy"
import KeyboardInput from "../components/KeyboardInput"
import ActionValues from "../enums/ActionValues"
import ActionQueue from "../components/ActionQueue"

export default class KeyboardInputSystem extends System {
  kb: KeyboardInput

  execute(): void {
    // Query for user action queue
    this.queries.keyboard.added.forEach(entity => {
      document.addEventListener("keydown", (e: KeyboardEvent) => {
        this.mapKeyToAction(entity, e.key, ActionValues.START)
      })
      document.addEventListener("keyup", (e: KeyboardEvent) => {
        this.mapKeyToAction(entity, e.key, ActionValues.END)
      })
    })
    this.queries.keyboard.removed.forEach(entity => {
      document.removeEventListener("keydown", (e: KeyboardEvent) => {
        this.mapKeyToAction(entity, e.key, ActionValues.START)
      })
      document.removeEventListener("keyup", (e: KeyboardEvent) => {
        this.mapKeyToAction(entity, e.key, ActionValues.END)
      })
    })
  }

  mapKeyToAction(entity: Entity, key: string, value: ActionValues): any {
    this.kb = entity.getComponent(KeyboardInput)
    if (this.kb.inputMap[key] === undefined) return

    // Add to action queue
    entity.getMutableComponent(ActionQueue).actions.add({
      action: this.kb.inputMap[key],
      value: value
    })
  }
}

KeyboardInputSystem.queries = {
  keyboard: {
    components: [KeyboardInput, ActionQueue],
    listen: { added: true, removed: true }
  }
}
