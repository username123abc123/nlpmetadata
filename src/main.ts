import { createApp, setModelStatus } from './ui/app';
import { configureLocalEnv, initEmbeddingModel } from './nlp/embeddingMapper';

const container = document.getElementById('app');
if (!container) throw new Error('Missing #app container');

configureLocalEnv(import.meta.env.BASE_URL);
createApp(container);

initEmbeddingModel()
  .then(() => setModelStatus('ready'))
  .catch((err) => {
    console.error('Embedding model failed to load; using heuristic fallback.', err);
    setModelStatus('failed');
  });
