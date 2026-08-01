import { useEffect, useState, type AnchorHTMLAttributes } from "react";

function currentPath(): string {
  const hash = window.location.hash.slice(1);
  return hash.startsWith("/") ? hash : "/";
}

export function useHashPath(): string {
  const [path, setPath] = useState(currentPath);
  useEffect(() => {
    const update = () => setPath(currentPath());
    window.addEventListener("hashchange", update);
    return () => window.removeEventListener("hashchange", update);
  }, []);
  return path;
}

export function Link({
  to,
  ...props
}: { to: string } & Omit<AnchorHTMLAttributes<HTMLAnchorElement>, "href">) {
  return <a href={`#${to}`} {...props} />;
}

