export class RoomDO extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
  }
  async fetch(request) {
    return new Response("RoomDO OK");
  }
}

export default {
  async fetch(request, env) {
    const id = env.ROOMS.idFromName("health");
    const stub = env.ROOMS.get(id);
    return stub.fetch(request);
  },
};
