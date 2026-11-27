import "@testing-library/jest-dom/vitest";

// jsdom does no layout: every element would measure 0 × 0 and count as
// hidden. Give elements a visible box unless a test sets `data-rect`
// ("zero" or "offscreen") to simulate the tricks hidden fields use.
const visible = { x: 10, y: 10, top: 10, left: 10, width: 200, height: 24, right: 210, bottom: 34 };
if (typeof Element !== "undefined") Element.prototype.getBoundingClientRect = function (this: Element) {
  const mode = this.getAttribute("data-rect");
  const rect =
    mode === "zero"
      ? { ...visible, width: 0, height: 0, right: 10, bottom: 10 }
      : mode === "offscreen"
        ? { ...visible, left: -5000, right: -4800, x: -5000 }
        : visible;
  return { ...rect, toJSON: () => rect } as DOMRect;
};
