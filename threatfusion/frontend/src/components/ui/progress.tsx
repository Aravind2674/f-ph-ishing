/**
 * Progress — shadcn-style linear progress track, monochrome.
 *
 * Value is 0..100. The indicator width is driven by the caller (often Framer
 * Motion) so count-up and bar-fill can stay in lockstep. No colour — fill is
 * off-white at controlled opacity via the design tokens.
 */
import * as React from "react";
import { cn } from "@/lib/utils";

export interface ProgressProps extends React.HTMLAttributes<HTMLDivElement> {
  /** 0..100 fill amount. */
  value?: number;
  /** Optional override for the indicator element (e.g. motion.div). */
  indicatorClassName?: string;
  /** When true, the indicator uses CSS width transition instead of jump. */
  animated?: boolean;
}

const Progress = React.forwardRef<HTMLDivElement, ProgressProps>(
  (
    { className, value = 0, indicatorClassName, animated = false, ...props },
    ref
  ) => {
    const clamped = Math.max(0, Math.min(100, value));
    return (
      <div
        ref={ref}
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={Math.round(clamped)}
        className={cn(
          "relative h-1.5 w-full overflow-hidden rounded-full bg-foreground/10",
          className
        )}
        {...props}
      >
        <div
          className={cn(
            "h-full rounded-full bg-foreground/55",
            animated && "transition-[width] duration-500 ease-out",
            indicatorClassName
          )}
          style={{ width: `${clamped}%` }}
        />
      </div>
    );
  }
);
Progress.displayName = "Progress";

export { Progress };
