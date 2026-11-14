import { useEffect, useState } from "react";

/** Tiny hash router: "#/product/3" -> ["product", "3"]. The staff Security Centre lives under "#/soc". */
const parse = () => location.hash.replace(/^#\/?/, "").split("?")[0].split("/").filter(Boolean);

export function useRoute() {
  const [parts, setParts] = useState<string[]>(parse);
  useEffect(() => {
    const f = () => { setParts(parse()); window.scrollTo?.(0, 0); document.getElementById("shop-scroll")?.scrollTo?.(0, 0); };
    window.addEventListener("hashchange", f);
    return () => window.removeEventListener("hashchange", f);
  }, []);
  return parts;
}

export const go = (path: string) => { location.hash = "#/" + path.replace(/^\/+/, ""); };
export const href = (path: string) => "#/" + path.replace(/^\/+/, "");
