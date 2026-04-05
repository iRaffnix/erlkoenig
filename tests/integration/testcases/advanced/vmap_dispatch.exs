defmodule Firewall.VmapDispatch do
  use ErlkoenigNft.Firewall
  firewall "test" do
    vmap "port_vmap", :inet_service, entries: [
      {80, :accept},
      {443, :accept}
    ]
    chain "input", hook: :input, policy: :drop do
      accept :established
      dispatch :tcp, "port_vmap"
    end
  end
end
