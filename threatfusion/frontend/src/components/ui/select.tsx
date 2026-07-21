import * as React from "react";
import { ChevronDown } from "lucide-react";
import { cn } from "@/lib/utils";

/*
 * A styled native <select>. We deliberately avoid a Radix/portal dropdown here:
 * the native control is fully accessible, dependency-free and keeps the build
 * lean. The chevron is overlaid; the native arrow is removed via `appearance-none`.
 */
const Select = React.forwardRef<
  HTMLSelectElement,
  React.SelectHTMLAttributes<HTMLSelectElement>
>(({ className, children, ...props }, ref) => (
  <div className="relative">
    <select
      ref={ref}
      className={cn(
        "h-10 w-full appearance-none rounded-md border border-line bg-surface-2 pl-3 pr-9 text-sm text-foreground",
        "transition-colors outline-none",
        "focus:border-line-strong focus:ring-2 focus:ring-ring/25",
        "disabled:cursor-not-allowed disabled:opacity-50",
        "[&>option]:bg-surface [&>option]:text-foreground",
        className
      )}
      {...props}
    >
      {children}
    </select>
    <ChevronDown className="pointer-events-none absolute right-3 top-1/2 size-4 -translate-y-1/2 text-subtle" />
  </div>
));
Select.displayName = "Select";

export { Select };
