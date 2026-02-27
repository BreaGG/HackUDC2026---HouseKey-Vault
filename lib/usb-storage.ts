const KEY_FILENAME = "housekeyvault.hkv";

export interface KeyFile {
  privateKeyB64: string;
  publicKeyB64: string;
  publicKeyHash: string;
  createdAt: number;
  version: number;
}

export function isFileSystemAccessSupported(): boolean {
  return typeof window !== "undefined" && "showDirectoryPicker" in window;
}

export async function setupUSBKey(keyFile: KeyFile): Promise<void> {
  // @ts-ignore
  const dirHandle: FileSystemDirectoryHandle = await window.showDirectoryPicker({
    mode: "readwrite", startIn: "desktop",
  });

  // Check no existing key
  try {
    await dirHandle.getFileHandle(KEY_FILENAME);
    throw new Error("This device already has a housekeyvault.hkv file. Use a different folder or delete it first.");
  } catch (e: any) {
    if (e.message.includes("already has")) throw e;
    // File doesn't exist — good, continue
  }

  const fileHandle = await dirHandle.getFileHandle(KEY_FILENAME, { create: true });
  const writable = await fileHandle.createWritable();
  await writable.write(JSON.stringify(keyFile, null, 2));
  await writable.close();
}

export async function loadUSBKey(): Promise<KeyFile> {
  // @ts-ignore
  const dirHandle: FileSystemDirectoryHandle = await window.showDirectoryPicker({
    mode: "read", startIn: "desktop",
  });

  let fileHandle: FileSystemFileHandle;
  try {
    fileHandle = await dirHandle.getFileHandle(KEY_FILENAME);
  } catch {
    throw new Error("No housekeyvault.hkv file found in the selected folder. Did you pick the right USB/directory?");
  }

  const file = await fileHandle.getFile();
  const text = await file.text();

  try {
    const keyFile = JSON.parse(text) as KeyFile;
    if (!keyFile.privateKeyB64 || !keyFile.publicKeyB64) throw new Error();
    return keyFile;
  } catch {
    throw new Error("Key file is corrupted or invalid.");
  }
}