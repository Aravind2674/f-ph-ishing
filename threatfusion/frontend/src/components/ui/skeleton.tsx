import { cn } from "@/lib/utils";

/*
 * Skeleton — a shimmering placeholder used for loading states instead of
 * spinners. The moving highlight is a low-opacity white sweep (see .tf-shimmer).
 */
function Skeleton({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "tf-shimmer relative overflow-hidden rounded bg-surface-2",
        className
      )}
      {...props}
    />
  );
}

export { Skeleton };
