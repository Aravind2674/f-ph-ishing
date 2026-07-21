import * as React from "react";
import { cn } from "@/lib/utils";

/*
 * Switch — a controlled monochrome toggle built on a native checkbox for
 * accessibility. "On" is a near-white track with a dark knob (high emphasis);
 * "off" is a hairline-bordered surface. No colour is used to convey state.
 */
export interface SwitchProps {
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  disabled?: boolean;
  id?: string;
  "aria-label"?: string;
}

const Switch = React.forwardRef<HTMLButtonElement, SwitchProps>(
  ({ checked, onCheckedChange, disabled, id, ...props }, ref) => (
    <button
      ref={ref}
      id={id}
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onCheckedChange(!checked)}
      className={cn(
        "relative inline-flex h-6 w-11 shrink-0 items-center rounded-full border transition-colors outline-none",
        "focus-visible:ring-2 focus-visible:ring-ring/40 disabled:cursor-not-allowed disabled:opacity-50",
        checked
          ? "border-transparent bg-foreground"
          : "border-line-strong bg-surface-2"
      )}
      {...props}
    >
      <span
        className={cn(
          "inline-block size-4 rounded-full transition-transform duration-200",
          checked ? "translate-x-6 bg-background" : "translate-x-1 bg-muted"
        )}
      />
    </button>
  )
);
Switch.displayName = "Switch";

export { Switch };
