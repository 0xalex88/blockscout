defmodule Explorer.Chain.SmartContract.Proxy.Basic do
  @moduledoc """
  Module for fetching proxy implementation from specific smart-contract getter
  """

  alias Explorer.SmartContract.Reader

  def get_implementation_address(signature, proxy_address_hash, abi) do
    implementation_address =
      case Reader.query_contract(
             proxy_address_hash,
             abi,
             %{
               "#{signature}" => []
             },
             false
           ) do
        %{^signature => {:ok, [result]}} -> result
        _ -> nil
      end

    address_to_hex(implementation_address)
  end

  defp address_to_hex(nil), do: nil

  defp address_to_hex(address) do
    if address do
      if String.starts_with?(address, "0x") do
        address
      else
        "0x" <> Base.encode16(address, case: :lower)
      end
    end
  end
end
