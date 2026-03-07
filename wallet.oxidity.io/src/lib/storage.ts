const hasChromeStorage =
  typeof chrome !== 'undefined' &&
  typeof chrome.storage !== 'undefined' &&
  typeof chrome.storage.local !== 'undefined';

function serialize<T>(value: T): string {
  return JSON.stringify(value);
}

function deserialize<T>(value: string | null): T | null {
  if (!value) {
    return null;
  }
  try {
    return JSON.parse(value) as T;
  } catch {
    return null;
  }
}

export async function loadJson<T>(key: string): Promise<T | null> {
  if (hasChromeStorage) {
    return new Promise((resolve) => {
      chrome.storage.local.get([key], (result) => {
        resolve(deserialize<T>(typeof result[key] === 'string' ? result[key] : null));
      });
    });
  }

  return deserialize<T>(window.localStorage.getItem(key));
}

export async function saveJson<T>(key: string, value: T): Promise<void> {
  const payload = serialize(value);

  if (hasChromeStorage) {
    await new Promise<void>((resolve) => {
      chrome.storage.local.set({ [key]: payload }, () => resolve());
    });
    return;
  }

  window.localStorage.setItem(key, payload);
}

export async function removeKey(key: string): Promise<void> {
  if (hasChromeStorage) {
    await new Promise<void>((resolve) => {
      chrome.storage.local.remove([key], () => resolve());
    });
    return;
  }

  window.localStorage.removeItem(key);
}
