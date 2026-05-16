"use client";

import * as React from "react";
import { Trash2, AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  AlertDialog,
  AlertDialogTrigger,
  AlertDialogContent,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogCancel,
  AlertDialogAction,
} from "@/components/ui/alert-dialog";

export function DeleteCell({
  product,
  onRemove,
}: Readonly<{
  product: { name: string; price: number; img: string };
  onRemove: (name: string) => void;
}>) {
  const [open, setOpen] = React.useState(false);
  const [confirmText, setConfirmText] = React.useState("");

  const matches = confirmText === product.name;

  React.useEffect(() => {
    if (!open) setConfirmText("");
  }, [open]);

  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <AlertDialogTrigger asChild>
        <Button
          variant="destructive"
          size="sm"
          className="gap-1"
          title={`Remove ${product.name}`}
        >
          <Trash2 className="w-4 h-4" />
          <span className="sr-only">Remove {product.name}</span>
        </Button>
      </AlertDialogTrigger>

      <AlertDialogContent className="sm:max-w-lg">
        <AlertDialogHeader>
          <AlertDialogTitle>Remove Product?</AlertDialogTitle>
          <AlertDialogDescription>
            This action removes the item from your cart. To confirm, type the product name exactly.
          </AlertDialogDescription>
        </AlertDialogHeader>


        {/* Danger note */}
        <div className="flex items-start gap-2 rounded-lg border border-destructive/30 bg-destructive/5 p-3">
          <AlertTriangle className="mt-0.5 h-4 w-4 text-destructive" />
          <p className="text-sm text-muted-foreground">
            You cannot undo this action. You can add the product again later from the catalog.
          </p>
        </div>

        {/* Confirm input */}
        <div className="space-y-2">
          <label htmlFor="confirm-delete" className="text-sm font-medium">
            Type product name to confirm
          </label>
          <Input
            id="confirm-delete"
            autoFocus
            value={confirmText}
            onChange={(e) => setConfirmText(e.target.value)}
            placeholder="Exact match required"
          />
          <p
            className={`text-xs ${
              confirmText.length === 0
                ? "text-muted-foreground"
                : matches
                ? "text-emerald-600"
                : "text-destructive"
            }`}
          >
            {confirmText.length === 0
              ? "Waiting for confirmation…"
              : matches
              ? "Name matches. You can remove this item."
              : "Name does not match."}
          </p>
        </div>

        <AlertDialogFooter>
          <AlertDialogCancel className="sm:mr-2">Cancel</AlertDialogCancel>
          <AlertDialogAction
            disabled={!matches}
            className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            onClick={() => {
              onRemove(product.name);
              setOpen(false);
            }}
          >
            Remove item
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
