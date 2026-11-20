// Composants partagés de Locksy (cahier 00, §2.9 et annexe B.1) : point
// d'entrée unique. Aucun composant n'importe vault.js, api.js,
// settings-client.js ni une vue : ils servent aussi à l'extension.

export { t, plural, has, tList, fmtDate, relTime, fmtNumber, fmtBytes, errorText, fieldErrorText } from "../i18n.js";
export { h, clear, icon, setIconBase, uid, initials, colorFor, TILE_COLORS, setHashParams } from "./core.js";
export { announce, liveRegion } from "./status.js";
export { keepFocus, focusHeading, focusables, focusSafely, isEditable, scrollParent } from "./focus.js";
export { hotkeys, HOTKEYS, keysLabel, parseKey, matches } from "./hotkeys.js";
export { button, iconButton, setDisabled, setPressed, busyWhile, isInactive } from "./button.js";
export { menuButton, openMenu } from "./menu.js";
export { field, fieldError, fieldInput, textInput, textArea, selectInput, describe } from "./field.js";
export { passwordField } from "./password.js";
export { otpInput, normalizeCode } from "./otp.js";
export { toggle, setToggle, segmented, radioCards, checkboxGroup } from "./choice.js";
export { durationSelect, formatDuration } from "./duration.js";
export { chipsInput } from "./chips.js";
export { searchBox, normalize } from "./search.js";
export { secretRow, copySecret, setClipboardPolicy, formatSecret, clearClipboardNow } from "./secret.js";
export { totpCode, groupCode } from "./totp.js";
export { strengthMeter, updateStrength, strengthLevel, strengthLabel, issueChip, issueText } from "./strength.js";
export { badge, audienceLine } from "./badges.js";
export { statCard, alertCard, statusCard } from "./cards.js";
export { emptyState, skeleton, errorState, offlineBanner, withLoading } from "./empty.js";
export { avatar, itemAvatar } from "./avatar.js";
export { dialog, closeAll, trackOverlay, modifiedDialog } from "./dialog.js";
export { confirm } from "./confirm.js";
export { panel } from "./panel.js";
export { popover, anchorHost } from "./popover.js";
export { tabs } from "./tabs.js";
export { sideNav, setNavCurrent } from "./sidenav.js";
export { wizard } from "./wizard.js";
export { itemList } from "./item-list.js";
export { dataTable } from "./table.js";
export { filterBar } from "./filters.js";
export { settingField, settingLabel, formatSettingValue, contrastRatio, accentCheck, closestAccent } from "./setting-field.js";
export { policyHint, policyText } from "./policy-hint.js";
export { diffList } from "./diff-list.js";
export { saveBar } from "./save-bar.js";
export { dirtyGuard } from "./dirty.js";
export { qrImport, decodeQrImage, setQrDecoderUrl } from "./qr.js";
export { notify, TONE_ICONS } from "./toast.js";
export { technicalDetails } from "./tech.js";
