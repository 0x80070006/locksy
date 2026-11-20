// Accueil : « Bonjour <prénom> » puis les tuiles du bilan (même analyse, sur le poste).
// Chaque tuile ouvre son détail sous les tuiles (voir health.js).

import * as H from "./health.js";

export const render = (ctx) => H.render(ctx, { dashboard: true });
