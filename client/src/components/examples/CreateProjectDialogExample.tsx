import { useState } from "react";
import { CreateProjectDialog } from "../CreateProjectDialog";
import { Button } from "@/components/ui/button";

export default function CreateProjectDialogExample() {
  const [open, setOpen] = useState(false);

  return (
    <>
      <Button onClick={() => setOpen(true)}>Open Create Project Dialog</Button>
      <CreateProjectDialog
        open={open}
        onOpenChange={setOpen}
        onSubmit={(data) => console.log("Project submitted:", data)}
      />
    </>
  );
}
