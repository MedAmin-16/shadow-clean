import { useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

interface CreateProjectDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSubmit?: (data: {
    name: string;
    description: string;
    targetUrl: string;
    assetType: string;
  }) => void;
}

export function CreateProjectDialog({ open, onOpenChange, onSubmit }: CreateProjectDialogProps) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [assetType, setAssetType] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // OPTIMISTIC UI: Immediately invalidate queries or show running state if possible
    // But since the mutation is handled by the parent, we'll let it handle the optimistic update
    onSubmit?.({ name, description, targetUrl, assetType });
    setName("");
    setDescription("");
    setTargetUrl("");
    setAssetType("");
    onOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[500px]">
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>Create New Twin Project</DialogTitle>
            <DialogDescription>
              Set up a new Digital Security Twin for your assets. The twin will monitor and simulate attacks on your infrastructure.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="name">Project Name</Label>
              <Input
                id="name"
                placeholder="e.g., Production API"
                value={name}
                onChange={(e) => setName(e.target.value)}
                data-testid="input-project-name"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="description">Description</Label>
              <Textarea
                id="description"
                placeholder="Describe the assets to be monitored..."
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                data-testid="input-project-description"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="targetUrl">Target URL</Label>
              <Input
                id="targetUrl"
                type="url"
                placeholder="https://api.example.com"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                data-testid="input-target-url"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="assetType">Asset Type</Label>
              <Select value={assetType} onValueChange={setAssetType}>
                <SelectTrigger data-testid="select-asset-type">
                  <SelectValue placeholder="Select asset type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="web-application">Web Application</SelectItem>
                  <SelectItem value="api">REST API</SelectItem>
                  <SelectItem value="cloud-infrastructure">Cloud Infrastructure</SelectItem>
                  <SelectItem value="network-services">Network Services</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" data-testid="button-create-project">
              Create Twin
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
