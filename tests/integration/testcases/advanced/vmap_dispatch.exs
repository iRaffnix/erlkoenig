defmodule Firewall.VmapDispatch do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    nft_vmap "port_vmap", :inet_service, [
      {80, :accept},
      {443, :accept}
    ]

    base_chain "input", hook: :input, type: :filter, priority: :filter, policy: :drop do
      nft_rule :accept, ct: :established
      nft_rule :vmap_dispatch, proto: :tcp, name: "port_vmap"
    end
  end
end
