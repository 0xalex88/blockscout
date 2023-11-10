defmodule Explorer.Chain.SmartContract.Proxy.MasterCopy do
  @moduledoc """
  Module for fetching master-copy proxy implementation
  """

  alias EthereumJSONRPC.Contract
  alias Explorer.Chain.Hash
  alias Explorer.Chain.SmartContract.Proxy

  @burn_address_hash_string_32 "0x0000000000000000000000000000000000000000000000000000000000000000"

  defguard is_burn_signature(term) when term in ["0x", "0x0", @burn_address_hash_string_32]

  @doc """
  Gets implementation address for proxy contract from master-copy pattern
  """
  @spec get_implementation_address(Hash.Address.t()) :: SmartContract.t() | nil
  def get_implementation_address(proxy_address_hash) do
    json_rpc_named_arguments = Application.get_env(:explorer, :json_rpc_named_arguments)

    master_copy_storage_pointer = "0x0"

    {:ok, implementation_address} =
      case Contract.eth_get_storage_at_request(
             proxy_address_hash,
             master_copy_storage_pointer,
             nil,
             json_rpc_named_arguments
           ) do
        {:ok, empty_address}
        when is_burn_signature(empty_address) ->
          {:ok, "0x"}

        {:ok, logic_contract_address} ->
          {:ok, logic_contract_address}

        _ ->
          {:ok, nil}
      end

    Proxy.abi_decode_address_output(implementation_address)
  end
end
