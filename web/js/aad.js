// Données associées : strictement identiques à crates/locksy-core/src/aad.rs.
export const userKey = () => "verrou:v1:user-key";
export const recoveryUserKey = () => "verrou:v1:recovery-user-key";
export const privateKey = (userId) => `verrou:v1:private-key:${userId}`;
export const collectionName = (cid) => `verrou:v1:collection-name:${cid}`;
export const item = (cid, iid) => `verrou:v1:item:${cid}:${iid}`;
export const collectionKey = (cid, uid) => `verrou:v1:collection-key:${cid}:${uid}`;
export const share = () => "verrou:v1:share";
export const attachment = (id) => `verrou:v1:attachment:${id}`;
export const prefs = (userId) => `verrou:v1:prefs:${userId}`;
