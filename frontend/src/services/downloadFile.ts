import client from "./api";

/** Fetches a URL as a blob and triggers a real browser download/save --
 * no precedent for this in the codebase before Reports, since no earlier
 * page ever downloaded a file. Used for both PDF and CSV downloads so the
 * "Download" buttons save actual generated files, not fake links. */
export async function downloadBlob(url: string, filename: string): Promise<void> {
  const response = await client.get(url, { responseType: "blob" });
  const blobUrl = URL.createObjectURL(response.data as Blob);
  const link = document.createElement("a");
  link.href = blobUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(blobUrl);
}

/** Opens a URL's blob content in a new browser tab (for "View Report"),
 * rather than forcing a download. The PDF requires an authenticated fetch
 * (Bearer token, not a cookie -- see services/api.ts's request interceptor),
 * so a plain `<a href>`/`window.open()` to the raw URL can't carry auth;
 * this fetches the blob first, then opens it. Deliberately an `<a
 * target="_blank">` click rather than `window.open()` + `location.href =
 * blobUrl` -- browsers silently refuse to navigate a separately-opened
 * window to a blob: URL it didn't create, whereas an anchor click with
 * target="_blank" is the standard, reliably-supported way to open blob
 * content in a new tab. */
export async function openBlobInNewTab(url: string): Promise<void> {
  const response = await client.get(url, { responseType: "blob" });
  const blobUrl = URL.createObjectURL(response.data as Blob);
  const link = document.createElement("a");
  link.href = blobUrl;
  link.target = "_blank";
  link.rel = "noopener";
  document.body.appendChild(link);
  link.click();
  link.remove();
}
