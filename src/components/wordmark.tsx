/**
 * Brand wordmark: "DEAMONIZE" in uppercase, where "DEAMON" is purple (brand
 * primary) and "IZE" is white in dark theme / black in light theme.
 */
export function Wordmark({ className }: { className?: string }) {
  return (
    <span className={className}>
      <span className="text-brand">DEAMON</span>
      <span className="text-foreground">IZE</span>
    </span>
  );
}
