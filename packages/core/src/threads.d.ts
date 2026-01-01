declare module "threads" {
  export {spawn, Thread, Worker, BlobWorker, Pool} from "threads/dist/master/index"
  export {Transfer} from "threads/dist/transferable"
}

declare module "threads/worker" {
  export {expose, isWorkerRuntime, registerSerializer} from "threads/dist/worker/index"
  export {Transfer} from "threads/dist/transferable"
}
