export default function Logo({ size = 36, withText = true, textSize = 22 }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
      <svg
        width={size}
        height={size}
        viewBox="0 0 64 64"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        aria-hidden
      >
        <rect width="64" height="64" rx="14" fill="#0a1628" />
        <path
          d="M18 20h10c8 0 14 5.5 14 12.5S36 45 28 45H18V20z"
          stroke="#00d4aa"
          strokeWidth="3.5"
          fill="none"
        />
        <circle cx="42" cy="32.5" r="5" fill="#00d4aa" />
        <path
          d="M42 27.5v-4M42 41.5v-4M37.5 32.5h-4M50.5 32.5h-4"
          stroke="#3b9eff"
          strokeWidth="2"
          strokeLinecap="round"
        />
      </svg>
      {withText && (
        <span
          style={{
            fontFamily: "var(--font-display)",
            fontWeight: 800,
            fontSize: textSize,
            letterSpacing: "-0.03em",
            lineHeight: 1,
          }}
        >
          Ciph<span style={{ color: "var(--accent)" }}>R</span>
        </span>
      )}
    </div>
  );
}
