import { useEffect, useRef } from "react";
import type { Wallpaper as WP } from "../os/context";

function MatrixRain({ animate, color }: { animate: boolean; color: string }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const c = ref.current!;
    const ctx = c.getContext("2d")!;
    let raf = 0;
    let last = 0;
    const size = 15;
    let cols = 0;
    let drops: number[] = [];
    const chars = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾅﾆﾇﾈﾉ01234567890ABCDEF<>/\\{}[]#$%";
    const resize = () => {
      c.width = c.offsetWidth;
      c.height = c.offsetHeight;
      cols = Math.ceil(c.width / size);
      drops = Array.from({ length: cols }, () => Math.random() * -50);
      ctx.fillStyle = "#020a08";
      ctx.fillRect(0, 0, c.width, c.height);
    };
    resize();
    const draw = (t: number) => {
      if (t - last > 55) {
        last = t;
        ctx.fillStyle = "rgba(2,10,8,0.12)";
        ctx.fillRect(0, 0, c.width, c.height);
        ctx.font = `${size}px JetBrains Mono, monospace`;
        for (let i = 0; i < cols; i++) {
          const ch = chars[Math.floor(Math.random() * chars.length)];
          const y = drops[i] * size;
          ctx.fillStyle = Math.random() > 0.96 ? "#e8fff6" : color;
          ctx.globalAlpha = 0.55;
          ctx.fillText(ch, i * size, y);
          ctx.globalAlpha = 1;
          if (y > c.height && Math.random() > 0.975) drops[i] = 0;
          drops[i]++;
        }
      }
      if (animate) raf = requestAnimationFrame(draw);
    };
    if (animate) raf = requestAnimationFrame(draw);
    else for (let i = 0; i < 60; i++) draw(i * 100);
    window.addEventListener("resize", resize);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
    };
  }, [animate, color]);
  return <canvas ref={ref} className="absolute inset-0 h-full w-full opacity-60" />;
}

export function Wallpaper({ kind, animate, accent }: { kind: WP; animate: boolean; accent: string }) {
  return (
    <div className="absolute inset-0 overflow-hidden bg-[#04080d]">
      {kind === "matrix" && (
        <>
          <MatrixRain animate={animate} color={accent} />
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,transparent_30%,#020608_95%)]" />
        </>
      )}
      {kind === "grid" && (
        <>
          <div className="absolute inset-0 bg-gradient-to-b from-[#07031a] via-[#12062e] to-[#1d0838]" />
          <div className="absolute left-1/2 top-[18%] h-52 w-52 -translate-x-1/2 rounded-full bg-gradient-to-b from-[#ff2bd6] to-[#ffb020] opacity-80 blur-[1px]" style={{ boxShadow: "0 0 120px 20px #ff2bd655" }} />
          <div className="absolute inset-x-0 bottom-0 h-[55%] overflow-hidden" style={{ perspective: 400 }}>
            <div
              className="absolute inset-x-[-50%] bottom-0 h-[200%] origin-bottom"
              style={{ transform: "rotateX(62deg)", backgroundImage: `linear-gradient(${accent}88 1px, transparent 1px), linear-gradient(90deg, ${accent}88 1px, transparent 1px)`, backgroundSize: "60px 60px", animation: animate ? "gridmove 2.5s linear infinite" : undefined }}
            />
          </div>
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,transparent_40%,#05010f_100%)]" />
        </>
      )}
      {kind === "aurora" && (
        <>
          <div className="absolute inset-0 bg-[#040a12]" />
          <div className="absolute -left-20 top-0 h-[70%] w-[60%] rounded-full opacity-50 blur-[110px]" style={{ background: accent, animation: animate ? "drift 14s ease-in-out infinite" : undefined }} />
          <div className="absolute -right-10 top-[20%] h-[60%] w-[55%] rounded-full bg-[#7c3aed] opacity-40 blur-[120px]" style={{ animation: animate ? "drift 18s ease-in-out infinite reverse" : undefined }} />
          <div className="absolute bottom-[-10%] left-[25%] h-[50%] w-[50%] rounded-full bg-[#00ffa3] opacity-25 blur-[120px]" style={{ animation: animate ? "drift 22s ease-in-out infinite" : undefined }} />
          <div className="grid-bg absolute inset-0 opacity-40" />
        </>
      )}
    </div>
  );
}
