import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

/*
 * Badge — solid gold for emphasis, outline or subtle otherwise.
 */
const badgeVariants = cva(
  "inline-flex items-center gap-1.5 rounded border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide2 transition-colors",
  {
    variants: {
      variant: {
        solid: "border-transparent bg-accent text-background font-semibold",
        outline: "border-line-strong bg-transparent text-foreground",
        subtle: "border-line bg-surface-2 text-muted",
        ghost: "border-transparent bg-transparent text-subtle",
      },
    },
    defaultVariants: {
      variant: "outline",
    },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <span className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}

export { Badge, badgeVariants };
