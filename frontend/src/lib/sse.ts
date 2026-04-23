// Minimal SSE consumer using fetch + streaming reader, because the browser's
// native EventSource cannot POST (we don't need that here since our events
// endpoint is GET, but this pattern gives us cleanup + cancellation for free
// on unmount).

export interface SseEvent {
  event: string;
  data: unknown;
}

export async function* subscribeToEvents(
  url: string,
  signal: AbortSignal,
): AsyncGenerator<SseEvent> {
  const response = await fetch(url, {
    method: "GET",
    headers: { Accept: "text/event-stream" },
    signal,
    cache: "no-store",
  });
  if (!response.ok || !response.body) {
    throw new Error(`SSE connection failed: HTTP ${response.status}`);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8");
  let buffer = "";

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) return;
      buffer += decoder.decode(value, { stream: true });

      // SSE events are delimited by a blank line.
      let boundary = buffer.indexOf("\n\n");
      while (boundary !== -1) {
        const chunk = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);

        let eventName = "message";
        const dataLines: string[] = [];
        for (const line of chunk.split("\n")) {
          const trimmed = line.replace(/\r$/, "");
          if (trimmed.startsWith(":")) continue; // keep-alive
          if (trimmed.startsWith("event:")) {
            eventName = trimmed.slice(6).trim();
          } else if (trimmed.startsWith("data:")) {
            dataLines.push(trimmed.slice(5).replace(/^\s/, ""));
          }
        }
        if (dataLines.length) {
          const raw = dataLines.join("\n");
          let data: unknown = raw;
          try {
            data = JSON.parse(raw);
          } catch {
            /* keep raw string */
          }
          yield { event: eventName, data };
        }

        boundary = buffer.indexOf("\n\n");
      }
    }
  } finally {
    reader.releaseLock();
  }
}
