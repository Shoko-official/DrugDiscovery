import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { App } from "./App";

describe("App", () => {
  it("starts in an honest runtime loading state outside browser preview mode", () => {
    const markup = renderToStaticMarkup(<App />);

    expect(markup).toContain("Desktop runtime");
    expect(markup).toContain("Loading decision review");
    expect(markup).not.toContain("Preview fixture");
  });
});
